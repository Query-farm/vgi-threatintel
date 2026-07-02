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
		{Name: "value", Position: 0, ArrowType: "varchar", Doc: "Indicator string (IP, domain, URL, or hash)"},
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
	Indicator string `vgi:"pos=0,doc=Indicator to look up (IP, domain, URL, or file hash)"`
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
			"vgi.result_columns_md": "| column | type | description |\n" +
				"|---|---|---|\n" +
				"| `indicator` | VARCHAR | The looked-up indicator, echoed back. |\n" +
				"| `type` | VARCHAR | IoC type as reported by the source (ipv4/ipv6/domain/url/md5/sha1/sha256). |\n" +
				"| `malicious` | BOOLEAN | Whether the source classifies the indicator as malicious. |\n" +
				"| `score` | DOUBLE | Reputation/threat score, or NULL when the source reports none. |\n" +
				"| `categories` | VARCHAR[] | Threat categories (e.g. `malware`, `phishing`, `c2`). |\n" +
				"| `source` | VARCHAR | Name of the reputation feed that produced the verdict. |\n" +
				"| `last_seen` | VARCHAR | When the source last observed the indicator (ISO-8601 string). |",
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

// Register registers all threat-intel functions (offline scalars + reputation
// table function).
func Register(w *vgi.Worker) {
	w.RegisterScalar(NewIndicatorTypeFunction())
	w.RegisterScalar(NewIsPrivateIPFunction())
	w.RegisterTable(NewReputationFunction())
}
