package sources

import (
	"context"
	"samoscout/pkg/session"
)


type Result struct {
	Type   string 
	Source string 
	Value  string 
	Error  error  
}


type Source interface {
	
	
	Run(ctx context.Context, domain string, s *session.Session) <-chan Result

	
	Name() string
}
