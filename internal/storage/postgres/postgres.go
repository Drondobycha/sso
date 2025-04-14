package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	pg_query "github.com/pganalyze/pg_query_go/v4"
)

type Storage struct {
	pool *pgxpool.Pool
}

const unique_violation = "23505"

func New(ctx context.Context, storagePath string) (*Storage, error) {
	const op = "storage.postgres.New"
	pool, err := pgxpool.New(ctx, storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &Storage{pool: pool}, nil
}

func ValidateSQLQuery(query string) error {
	const op = "storage.postgres.ValidateSQLQuery"
	res, err := pg_query.Parse(query)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	str := res.String()
	fmt.Printf("str = \n%s", str)
	return err
}
