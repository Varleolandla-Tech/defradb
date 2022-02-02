package query

import (
	"context"
	"testing"

	"github.com/sourcenetwork/defradb/bench/fixtures"
)

var (
	userSimpleQuery = `
	query {
		User {
			_key
			Name
			Age
			Points
			Verified
		}
	}
	`
)

func Benchmark_Query_UserSimple_Query_Sync_1(b *testing.B) {
	ctx := context.Background()
	err := runQueryBenchGet(b, ctx, fixtures.ForSchema(ctx, "user_simple"), 1, userSimpleQuery, false)
	if err != nil {
		b.Fatal(err)
	}
}

func Benchmark_Query_UserSimple_Query_Sync_10(b *testing.B) {
	ctx := context.Background()
	err := runQueryBenchGet(b, ctx, fixtures.ForSchema(ctx, "user_simple"), 10, userSimpleQuery, false)
	if err != nil {
		b.Fatal(err)
	}
}

func Benchmark_Query_UserSimple_Query_Sync_100(b *testing.B) {
	ctx := context.Background()
	err := runQueryBenchGet(b, ctx, fixtures.ForSchema(ctx, "user_simple"), 100, userSimpleQuery, false)
	if err != nil {
		b.Fatal(err)
	}
}

func Benchmark_Query_UserSimple_Query_Sync_1000(b *testing.B) {
	ctx := context.Background()
	err := runQueryBenchGet(b, ctx, fixtures.ForSchema(ctx, "user_simple"), 1000, userSimpleQuery, false)
	if err != nil {
		b.Fatal(err)
	}
}
