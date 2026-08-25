package server

import (
	"encoding/json"
	"sort"
)

const (
	// outlineDepth bounds how deep the outline describes, so it cannot reproduce the
	// problem it exists to describe.
	outlineDepth = 3

	// outlineFields caps how many fields are reported, heaviest first.
	outlineFields = 25
)

// outline describes a response that could not be brought within budget: its size, its row
// count, and where its weight actually sits.
//
// It carries no suggested retry. The only responses that reach here are oversized for a
// reason arrays cannot fix — one enormous string, or thousands of distinct scalar keys —
// and for a single-record query there is no narrower query to suggest. Saying what the
// record looks like is what tells a model the record is pathological rather than its query
// being wrong.
type outline struct {
	Bytes int           `json:"bytes"`
	Rows  int           `json:"rows"`
	Shape []fieldWeight `json:"shape"`
}

type fieldWeight struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Items   int    `json:"items,omitempty"`
	Bytes   int    `json:"bytes"`
	Percent int    `json:"percent"`
}

// outlineResponse reports the shape and weight of a decoded response.
//
// It walks the tree the caller has already decoded, so it costs one pass and no second
// decode. Arrays are described by a single representative element rather than by every
// element, for the same reason the outline is bounded at all.
func outlineResponse(root any, rowPath string, totalBytes int) *outline {
	weights := map[string]fieldWeight{}
	weigh(root, "", 0, weights)

	// The row list and the document root contain everything else, so they would always
	// rank first and say nothing. What is worth reporting is which field inside a record
	// carries the weight.
	delete(weights, "")
	delete(weights, rowPath)

	shape := make([]fieldWeight, 0, len(weights))
	for _, w := range weights {
		if totalBytes > 0 {
			w.Percent = w.Bytes * 100 / totalBytes
		}
		shape = append(shape, w)
	}

	// Heaviest first, then by path, so the same response always produces the same outline.
	sort.Slice(shape, func(i, j int) bool {
		if shape[i].Bytes != shape[j].Bytes {
			return shape[i].Bytes > shape[j].Bytes
		}
		return shape[i].Path < shape[j].Path
	})
	if len(shape) > outlineFields {
		shape = shape[:outlineFields]
	}

	rows := 0
	if list, ok := rowsAt(root, rowPath); ok {
		rows = len(list)
	}

	return &outline{Bytes: totalBytes, Rows: rows, Shape: shape}
}

// weigh records the serialized size of each field, to the depth cap.
//
// Each node is recorded exactly once, by its parent. Recording it twice — once as a child
// and again as a container — meant the second call lost to the "keep the heaviest" guard on
// equal bytes, and with it the array length, which is the single most useful number here.
func weigh(v any, path string, depth int, out map[string]fieldWeight) {
	if depth > outlineDepth {
		return
	}

	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			childPath := path + "/" + escapeToken(k)
			record(childPath, child, out)
			weigh(child, childPath, depth+1, out)
		}

	case []any:
		// One representative element: rows within an index are homogeneous, so
		// describing every one of them would be the problem this is describing.
		if len(t) > 0 {
			weigh(t[0], path+"/-", depth+1, out)
		}
	}
}

func record(path string, v any, out map[string]fieldWeight) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return
	}
	// Keep the heaviest instance of a path shared by many rows.
	if prev, ok := out[path]; ok && prev.Bytes >= len(encoded) {
		return
	}
	items := 0
	if arr, ok := v.([]any); ok {
		items = len(arr)
	}
	out[path] = fieldWeight{
		Path:  path,
		Type:  jsonType(v),
		Items: items,
		Bytes: len(encoded),
	}
}

func jsonType(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		return "number"
	}
}
