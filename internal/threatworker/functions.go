// Copyright 2026 Query Farm LLC - https://query.farm

package threatworker

import (
	"context"
	"time"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-rpc-go/vgirpc"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// Compile-time checks: the offline scalars implement vgi.ScalarFunction
// directly (no typed wrapper needed), so RegisterScalar can take them as-is.
var (
	_ vgi.ScalarFunction = (*IndicatorTypeFunction)(nil)
	_ vgi.ScalarFunction = (*IsPrivateIPFunction)(nil)
)

// CatalogName is the VGI catalog name advertised by this worker.
const CatalogName = "threatintel"

// IMPORTANT (gob-state gotcha): table-function state is gob-encoded by the SDK
// between NewState and Process (it may cross a process boundary). State structs
// must therefore hold only EXPORTED, gob-encodable fields — no arrow.Record, no
// interfaces, channels, funcs, or unexported fields. The reputation table
// function fetches its row eagerly in NewState, stores plain exported Go slices
// plus a Done flag, and rebuilds the Arrow batch in Process.

// WHY AN EXPLICIT CURSOR, NOT A bool Done (the HTTP-continuation fix):
//
// Over the HTTP transport the worker is STATELESS across exchanges — there is no
// long-lived process holding the live state between Process ticks. The framework
// round-trips the producer state through an opaque continuation token: after each
// tick it gob-encodes the state (snapshotting the LIVE user state), the client
// returns the token, and the worker resumes by gob-decoding it. The HTTP server
// emits at most one data batch per response, so a producer with more to emit is
// always resumed mid-stream from its token.
//
// The position MUST therefore live in the serialized state. A bare `Done bool`
// flipped only AFTER the single Emit does not survive the continuation boundary:
// the resumed tick observes the pre-Emit snapshot, re-emits the same rows, and
// the scan never terminates (an infinite loop — subprocess/unix keep live state
// in memory, so they were unaffected and hid the bug). Carrying an explicit
// Offset that Process advances BEFORE yielding makes the snapshot authoritative.
//
// rowsPerTick bounds how many rows each Process tick emits, so the cursor is
// observable across the continuation boundary. (reputation returns at most one
// row, but the cursor is the correct general pattern and is HTTP-safe.)
const rowsPerTick = 256

// cursorSlice returns the next bounded slice of rows starting at *offset and
// advances *offset past them, reporting done=true once all rows are consumed.
func cursorSlice[T any](rows []T, offset *int) (slice []T, done bool) {
	if *offset >= len(rows) {
		return nil, true
	}
	end := *offset + rowsPerTick
	if end > len(rows) {
		end = len(rows)
	}
	slice = rows[*offset:end]
	*offset = end
	return slice, false
}

// ===========================================================================
// Offline scalar functions (no network) — indicator typing / triage.
// ===========================================================================

// ---------------------------------------------------------------------------
// indicator_type(value VARCHAR) -> VARCHAR
// ---------------------------------------------------------------------------

// IndicatorTypeFunction classifies an indicator string into an IoC type.
type IndicatorTypeFunction struct{}

func (f *IndicatorTypeFunction) Name() string { return "indicator_type" }

func (f *IndicatorTypeFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Classify an indicator as ipv4/ipv6/domain/url/md5/sha1/sha256, or NULL if unrecognized",
		Stability:   vgi.StabilityConsistent,
		ReturnType:  arrow.BinaryTypes.String,
		Categories:  []string{"threatintel", "ioc"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT threatintel.main.indicator_type('8.8.8.8');",
				Description: "Classify an IPv4 address; returns 'ipv4'.",
			},
			{
				SQL:         "SELECT threatintel.main.indicator_type('44d88612fea8a8f36de82e1278abb02f');",
				Description: "Classify a 32-hex-character file hash as 'md5'.",
			},
		},
		Tags: objectTags(
			"Classify Indicator Type",
			"Classify a single cyber indicator (IoC) string into its type: ipv4, ipv6, "+
				"domain, url, md5, sha1, or sha256. Returns NULL for an unrecognized or "+
				"NULL input. Pure and offline (no network); use it to triage and route a "+
				"column of indicators before spending reputation-API budget.",
			"Classify an indicator string as `ipv4`/`ipv6`/`domain`/`url`/`md5`/`sha1`/"+
				"`sha256`, or `NULL` if unrecognized. Offline and deterministic.",
			"Offline Triage",
			[]string{
				"indicator type", "ioc", "classify", "ipv4", "ipv6", "domain", "url",
				"hash", "md5", "sha1", "sha256", "triage", "threat intel",
				"threat hunting", "soc",
			},
		),
	}
}

func (f *IndicatorTypeFunction) ArgumentSpecs() []vgi.ArgSpec {
	return []vgi.ArgSpec{
		// NOTE (VGI317): the accepted input is an OPEN set — any free-form
		// observable string — so we describe the KINDS of observable with a
		// slash-delimited phrase rather than a comma "…, or …" enumeration
		// that would (correctly) be read as a fixed vocabulary needing a
		// machine-readable `choices` constraint. There is no closed list here:
		// the type is inferred from the value's shape and an unrecognized
		// string yields NULL.
		{Name: "value", Position: 0, ArrowType: "varchar", Doc: "A single indicator observable to classify. An IP address / domain name / URL / file-hash string is accepted; the type is inferred from the value's shape and an unrecognized string returns NULL."},
	}
}

func (f *IndicatorTypeFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindResult(arrow.BinaryTypes.String)
}

func (f *IndicatorTypeFunction) Process(_ context.Context, params *vgi.ProcessParams, batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	// An unrecognized indicator (or a NULL input) yields "" from IndicatorType,
	// which we surface as SQL NULL (not the empty string) so callers can filter
	// with IS NULL. We build the output array directly to control null output.
	col := batch.Column(0)
	n := int(batch.NumRows())
	b := array.NewStringBuilder(memory.NewGoAllocator())
	defer b.Release()
	b.Reserve(n)
	for i := 0; i < n; i++ {
		if col.IsNull(i) {
			b.AppendNull()
			continue
		}
		t := IndicatorType(vgi.GetStringValue(col, i))
		if t == "" {
			b.AppendNull()
		} else {
			b.Append(t)
		}
	}
	arr := b.NewArray()
	defer arr.Release()
	return array.NewRecordBatch(params.OutputSchema, []arrow.Array{arr}, int64(n)), nil
}

// NewIndicatorTypeFunction builds the registerable scalar function.
func NewIndicatorTypeFunction() vgi.ScalarFunction { return &IndicatorTypeFunction{} }

// ---------------------------------------------------------------------------
// is_private_ip(value VARCHAR) -> BOOLEAN
// ---------------------------------------------------------------------------

// IsPrivateIPFunction reports whether an indicator is a private/reserved IP.
type IsPrivateIPFunction struct{}

func (f *IsPrivateIPFunction) Name() string { return "is_private_ip" }

func (f *IsPrivateIPFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Report whether an indicator is a private/reserved IP (RFC1918/loopback/etc.); false for non-IPs",
		Stability:   vgi.StabilityConsistent,
		ReturnType:  arrow.FixedWidthTypes.Boolean,
		Categories:  []string{"threatintel", "ioc"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT threatintel.main.is_private_ip('10.0.0.5');",
				Description: "An RFC1918 address is private; returns true.",
			},
			{
				SQL:         "SELECT threatintel.main.is_private_ip('8.8.8.8');",
				Description: "A routable public address; returns false (safe to look up).",
			},
		},
		Tags: objectTags(
			"Is Private Reserved IP",
			"Report whether an indicator is an IP literal in a private or reserved range "+
				"(RFC1918, loopback, link-local, CGNAT, documentation/TEST-NET, multicast, "+
				"IPv6 ULA, etc.). Returns false for any non-IP input. Pure and offline; "+
				"gate a public reputation lookup on NOT is_private_ip(x) so internal hosts "+
				"don't waste API budget.",
			"Report whether an indicator is a private/reserved IP "+
				"(RFC1918/loopback/CGNAT/TEST-NET/…); `false` for non-IPs. Offline.",
			"Offline Triage",
			[]string{
				"private ip", "reserved ip", "rfc1918", "loopback", "link-local",
				"cgnat", "test-net", "documentation range", "internal host",
				"triage", "ip filter", "threat intel", "soc",
			},
		),
	}
}

func (f *IsPrivateIPFunction) ArgumentSpecs() []vgi.ArgSpec {
	return []vgi.ArgSpec{
		{Name: "value", Position: 0, ArrowType: "varchar", Doc: "IP literal to test"},
	}
}

func (f *IsPrivateIPFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindResult(arrow.FixedWidthTypes.Boolean)
}

func (f *IsPrivateIPFunction) Process(_ context.Context, params *vgi.ProcessParams, batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	return vgi.MapColumn(params, batch, 0, array.NewBooleanBuilder,
		func(col arrow.Array, i int) bool {
			return IsPrivateIP(vgi.GetStringValue(col, i))
		})
}

// NewIsPrivateIPFunction builds the registerable scalar function.
func NewIsPrivateIPFunction() vgi.ScalarFunction { return &IsPrivateIPFunction{} }

// ===========================================================================
// Table function (reputation API) — named base_url / api_key / timeout_ms opts.
// ===========================================================================

// ---------------------------------------------------------------------------
// reputation(indicator) -> (indicator, type, malicious, score, categories,
//                           source, last_seen)
// ---------------------------------------------------------------------------

var reputationSchema = arrow.NewSchema([]arrow.Field{
	{Name: "indicator", Type: arrow.BinaryTypes.String},
	{Name: "type", Type: arrow.BinaryTypes.String},
	{Name: "malicious", Type: arrow.FixedWidthTypes.Boolean},
	{Name: "score", Type: arrow.PrimitiveTypes.Float64, Nullable: true},
	{Name: "categories", Type: arrow.ListOf(arrow.BinaryTypes.String)},
	{Name: "source", Type: arrow.BinaryTypes.String},
	{Name: "last_seen", Type: arrow.BinaryTypes.String},
}, nil)

type reputationArgs struct {
	// The indicator input is an OPEN set (any observable string), so the doc is
	// slash-delimited rather than a comma "…, or …" list (VGI317): there is no
	// closed vocabulary to declare as `choices`. (Slash form also keeps commas
	// out of the vgi struct-tag, which is comma-separated.)
	Indicator string `vgi:"pos=0,doc=A single indicator observable to look up against the reputation source. An IP address / domain name / URL / file-hash string is accepted; private/reserved and unrecognized inputs return zero rows without a network call."`
	BaseURL   string `vgi:"name=base_url,default=,doc=Override the reputation API base URL"`
	APIKey    string `vgi:"name=api_key,default=,doc=API key for the reputation source (if required)"`
	TimeoutMS int64  `vgi:"name=timeout_ms,default=15000,doc=Per-request HTTP timeout in milliseconds"`
}

// reputationState holds the at-most-one fetched verdict (gob-encodable) plus the
// cursor offset of the next unemitted row.
type reputationState struct {
	Rows   []RepRow
	Offset int
}

// ReputationFunction looks up one indicator against the reputation source.
type ReputationFunction struct{}

var _ vgi.TypedTableFunc[reputationState] = (*ReputationFunction)(nil)

func (f *ReputationFunction) Name() string { return "reputation" }

func (f *ReputationFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Look up one indicator against a threat-intel reputation source; returns at most one verdict row",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"threatintel", "reputation"},
		Examples: []vgi.CatalogExample{
			// These examples are chosen to execute cleanly WITHOUT a live reputation
			// backend: a private/reserved IP and an unsupported indicator are triaged
			// to zero rows in NewState BEFORE any network call (the worker never
			// spends lookup budget on internal hosts or non-indicators). A real,
			// backend-qualified lookup (an external IP/domain/hash against a
			// configured base_url) is documented in vgi.example_queries / columns_md.
			{
				SQL:         "SELECT count(*) AS rows_for_private_ip FROM threatintel.main.reputation('10.0.0.5');",
				Description: "A private/reserved IP is triaged to zero verdict rows before any network call (no public-reputation budget spent on internal hosts); count(*) returns 0.",
			},
			{
				SQL:         "SELECT count(*) AS rows_for_unsupported FROM threatintel.main.reputation('not-an-indicator');",
				Description: "An unsupported indicator string yields zero verdict rows (no lookup); count(*) returns 0.",
			},
		},
		Tags: mergeTags(objectTags(
			"Indicator Reputation Lookup",
			"Look up one cyber indicator (IP, domain, URL, or file hash) against a "+
				"threat-intel reputation source and return at most one verdict row: "+
				"indicator, type, malicious flag, score, categories, source, and "+
				"last_seen. Private/reserved IPs and unsupported strings are triaged to "+
				"zero rows before any network call; an unknown indicator (source 404) "+
				"also yields zero rows. The source is a normalized reputation endpoint "+
				"selected with the base_url option (api_key / timeout_ms also named).",
			"Look up an indicator against a threat-intel reputation source; returns at "+
				"most one verdict row (`malicious`, `score`, `categories`, `source`, "+
				"`last_seen`). Configure the feed with `base_url` (+ `api_key`).",
			"Reputation Enrichment",
			[]string{
				"reputation", "threat intel", "ioc lookup", "indicator enrichment",
				"malicious", "threat score", "categories", "ip reputation",
				"domain reputation", "url", "file hash", "otx", "urlhaus",
				"threatfox", "virustotal", "soc", "threat hunting",
			},
		), map[string]string{
			// VGI307/VGI321: this table function has a static result schema, so
			// declare it as the structured vgi.result_columns_schema (a JSON
			// array of {name,type,description}). The legacy free-form
			// vgi.result_columns_md is retired (VGI414). Types mirror
			// reputationSchema exactly so VGI910 (schema matches what the
			// function returns, under --execute) stays satisfied.
			"vgi.result_columns_schema": `[` +
				`{"name":"indicator","type":"VARCHAR","description":"The looked-up indicator, echoed back."},` +
				`{"name":"type","type":"VARCHAR","description":"IoC type as reported by the source (ipv4/ipv6/domain/url/md5/sha1/sha256)."},` +
				`{"name":"malicious","type":"BOOLEAN","description":"Whether the source classifies the indicator as malicious."},` +
				`{"name":"score","type":"DOUBLE","description":"Reputation/threat score, or NULL when the source reports none."},` +
				`{"name":"categories","type":"VARCHAR[]","description":"Threat categories the source assigned (for example malware, phishing, or c2)."},` +
				`{"name":"source","type":"VARCHAR","description":"Name of the reputation feed that produced the verdict."},` +
				`{"name":"last_seen","type":"VARCHAR","description":"When the source last observed the indicator (ISO-8601 string)."}` +
				`]`,
		}),
	}
}

func (f *ReputationFunction) ArgumentSpecs() []vgi.ArgSpec {
	return vgi.DeriveArgSpecs(reputationArgs{})
}

func (f *ReputationFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(reputationSchema)
}

func (f *ReputationFunction) NewState(params *vgi.ProcessParams) (*reputationState, error) {
	var args reputationArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	// A NULL indicator yields no rows (not an error).
	if isNullArg(params.Args, 0) {
		return &reputationState{}, nil
	}

	// Offline triage: skip the lookup for unsupported indicators and for
	// private/reserved IPs (no public-reputation budget wasted on internal
	// hosts). Both cases yield zero rows rather than an error, so a batch
	// LATERAL join over a column of indicators simply drops them.
	if IndicatorType(args.Indicator) == "" || IsPrivateIP(args.Indicator) {
		return &reputationState{}, nil
	}

	client := NewClient(args.BaseURL, args.APIKey, time.Duration(args.TimeoutMS)*time.Millisecond)
	row, err := client.Reputation(context.Background(), args.Indicator)
	if err != nil {
		return nil, err
	}
	if row == nil {
		// Unknown indicator (404): no verdict, no rows.
		return &reputationState{}, nil
	}
	return &reputationState{Rows: []RepRow{*row}}, nil
}

func (f *ReputationFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *reputationState, out *vgirpc.OutputCollector) error {
	r, done := cursorSlice(state.Rows, &state.Offset)
	if done {
		return out.Finish()
	}
	n := int64(len(r))
	batch := array.NewRecordBatch(reputationSchema, []arrow.Array{
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Indicator }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Type }),
		vgi.BuildBooleanArray(n, func(i int64) bool { return r[i].Malicious }),
		buildNullableScore(r),
		buildStringListArray(r),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Source }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].LastSeen }),
	}, n)
	defer batch.Release()
	return out.Emit(batch)
}

// NewReputationFunction builds the registerable table function.
func NewReputationFunction() vgi.TableFunction {
	return vgi.AsTableFunction[reputationState](&ReputationFunction{})
}

// ===========================================================================
// helpers
// ===========================================================================

// buildNullableScore builds a Float64 array where a nil Score yields SQL NULL,
// so a source that returns no numeric score surfaces NULL rather than 0.
func buildNullableScore(rows []RepRow) arrow.Array {
	b := array.NewFloat64Builder(memory.NewGoAllocator())
	defer b.Release()
	b.Reserve(len(rows))
	for _, r := range rows {
		if r.Score == nil {
			b.AppendNull()
		} else {
			b.Append(*r.Score)
		}
	}
	return b.NewArray()
}

// buildStringListArray builds a List<String> array (categories VARCHAR[]) — one
// list per row, in row order.
func buildStringListArray(rows []RepRow) arrow.Array {
	lb := array.NewListBuilder(memory.NewGoAllocator(), arrow.BinaryTypes.String)
	defer lb.Release()
	vb := lb.ValueBuilder().(*array.StringBuilder)
	for _, r := range rows {
		lb.Append(true)
		for _, cat := range r.Categories {
			vb.Append(cat)
		}
	}
	return lb.NewArray()
}

// isNullArg reports whether positional argument pos is present and NULL.
func isNullArg(args *vgi.Arguments, pos int) bool {
	if args == nil {
		return true
	}
	col, err := args.GetColumn(pos)
	if err != nil {
		return false
	}
	return col.Len() == 0 || col.IsNull(0)
}

// ===========================================================================
// Browsable reference view (VGI146) — indicator_types.
// ===========================================================================
//
// A worker that exposes only functions/table-functions gives an agent nothing
// to LIST and scan before it has to guess arguments (VGI146). indicator_types
// is a small, curated, VALUES-backed reference view: it enumerates every IoC
// type that indicator_type() can return, each with a short description and a
// canonical example. Being VALUES-backed it scans with NO network or credential
// (so it also clears VGI911 for free), and it is a real view (iter_table_like),
// not a parameterless table-function wrapper (which VGI145 would flag).

// indicatorTypesViewDef is the SQL backing the indicator_types view. It is a
// static VALUES relation aliased to the view's three columns. The rows are the
// exact closed set of types IndicatorType can emit, so the view documents the
// classifier's output space and can be browsed offline.
const indicatorTypesViewDef = `SELECT * FROM (VALUES
  ('ipv4',   'IPv4 address in dotted-quad notation',                    '8.8.8.8'),
  ('ipv6',   'IPv6 address in colon-hex notation',                      '2001:4860:4860::8888'),
  ('domain', 'DNS domain name (hostname)',                              'example.com'),
  ('url',    'Absolute HTTP or HTTPS URL',                              'https://example.com/path'),
  ('md5',    'MD5 file hash (32 hexadecimal characters)',               '44d88612fea8a8f36de82e1278abb02f'),
  ('sha1',   'SHA-1 file hash (40 hexadecimal characters)',             'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
  ('sha256', 'SHA-256 file hash (64 hexadecimal characters)',           'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
) AS t(indicator_type, description, example)`

// indicatorTypesExampleQueries is the object-level vgi.example_queries for the
// indicator_types view (VGI502: a JSON array of {description, sql}). It CALLS
// the view (VGI511) with an explicit column projection and ORDER BY rather than
// a bare SELECT * (VGI514), and is fully catalog-qualified so it counts toward
// coverage and executes under --execute.
const indicatorTypesExampleQueries = `[
  {
    "description": "List every IoC type the worker recognizes, with a description and a canonical example of each.",
    "sql": "SELECT indicator_type, description, example FROM threatintel.main.indicator_types ORDER BY indicator_type"
  },
  {
    "description": "Look up the canonical example and human description for a single indicator type (sha256).",
    "sql": "SELECT description, example FROM threatintel.main.indicator_types WHERE indicator_type = 'sha256'"
  }
]`

// registerIndicatorTypesView registers the indicator_types reference view.
func registerIndicatorTypesView(w *vgi.Worker) {
	w.RegisterCatalogView("main", vgi.CatalogView{
		Name:       "indicator_types",
		Definition: indicatorTypesViewDef,
		Comment: "Reference table of the indicator (IoC) types this worker classifies — the exact " +
			"closed set of values indicator_type() can return — each with a description and a " +
			"canonical example. Browse it to learn the classifier's output space; VALUES-backed, " +
			"so it scans offline with no network call.",
		ColumnComments: map[string]string{
			"indicator_type": "The IoC type name, one of the values indicator_type() emits (ipv4/ipv6/domain/url/md5/sha1/sha256).",
			"description":    "Human-readable description of the indicator type.",
			"example":        "A canonical example value of this indicator type.",
		},
		Tags: mergeTags(objectTags(
			"Supported Indicator Types",
			"Curated reference view enumerating every indicator (IoC) type the worker classifies — "+
				"ipv4, ipv6, domain, url, md5, sha1, and sha256 — the exact closed set of values the "+
				"indicator_type scalar can return. Each row carries the type name, a human-readable "+
				"description, and a canonical example. VALUES-backed, so it browses offline with no "+
				"network access; use it to discover what indicator_type can classify a string into "+
				"before enriching.",
			"A reference view listing every IoC type the worker recognizes (`ipv4`/`ipv6`/`domain`/"+
				"`url`/`md5`/`sha1`/`sha256`), with a description and a canonical example of each. "+
				"VALUES-backed and offline; it documents the exact output space of `indicator_type`.",
			"Offline Triage",
			[]string{
				"indicator types", "ioc types", "reference", "catalog", "ipv4", "ipv6",
				"domain", "url", "md5", "sha1", "sha256", "classify", "vocabulary",
				"threat intel", "soc",
			},
		), map[string]string{
			"vgi.example_queries": indicatorTypesExampleQueries,
			// VGI123 classifying tags MUST use BARE keys (not vgi.-namespaced),
			// and reuse the schema's vocabulary so the facet stays a small
			// shared set rather than a per-object value (VGI727).
			"domain": "security",
			"topic":  "indicator-enrichment",
		}),
	})
}

// Register registers all threat-intel functions (offline scalars + reputation
// table function) plus the indicator_types reference view.
func Register(w *vgi.Worker) {
	w.RegisterScalar(NewIndicatorTypeFunction())
	w.RegisterScalar(NewIsPrivateIPFunction())
	w.RegisterTable(NewReputationFunction())
	registerIndicatorTypesView(w)
}
