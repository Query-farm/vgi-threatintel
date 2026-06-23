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

// emitState carries the "already emitted" flag for table functions.
type emitState struct {
	Done bool
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
// emit flag.
type reputationState struct {
	emitState
	Rows []RepRow
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
	if state.Done {
		return out.Finish()
	}
	state.Done = true
	r := state.Rows
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
