package authzfilter

import (
	"github.com/Sirupsen/logrus"
	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/gobwas/glob"
	"github.com/pkg/errors"
)

type PrincipalFilterConfig struct {
	Name string
	// 1. Filter out principals that do not match this glob
	FilterIncludePrincipalsGlob string
	// 2. Filter out principals that match this glob
	FilterExcludePrincipalsGlob string
	// 3. Fail if no principal matches this glob
	MustIncludePrincipalGlob string
	// 4. Fail if any principal matches this glob
	MustNotIncludePrincipalGlob string
}

type PrincipalFilter struct {
	filterInclude  glob.Glob
	filterExclude  glob.Glob
	mustInclude    glob.Glob
	mustNotInclude glob.Glob
	config         PrincipalFilterConfig
	log            *logrus.Entry
}

func (pf *PrincipalFilter) Authorize(actx *auth.AuthContext) (*auth.AuthContext, bool) {
	if actx == nil {
		return nil, false
	}
	log := pf.log.WithField("action", "authorize")
	var removePrincipals []string
	principals := actx.GetPrincipals()
	if pf.filterInclude != nil {
		filtered := principals[:0]
		for _, v := range principals {
			if !pf.filterInclude.Match(v) {
				removePrincipals = append(removePrincipals, v)
				log.WithField("principal", v).Debug("remove")
			} else {
				filtered = append(filtered, v)
			}
		}
		principals = filtered
	}
	if pf.filterExclude != nil {
		filtered := principals[:0]
		for _, v := range principals {
			if pf.filterExclude.Match(v) {
				removePrincipals = append(removePrincipals, v)
				log.WithField("principal", v).Debug("remove")
			} else {
				filtered = append(filtered, v)
			}
		}
		principals = filtered
	}
	if pf.mustInclude != nil {
		log.Debug("check mustInclude")
		match := false
		for _, v := range principals {
			if pf.mustInclude.Match(v) {
				match = true
				log.WithField("principal", v).Debug("must include")
			}
		}
		if !match {
			log.Debug("mustInclude failed")
			return nil, false
		}
	}
	if pf.mustNotInclude != nil {
		log.Debug("check mustNotInclude")
		match := false
		for _, v := range principals {
			if pf.mustNotInclude.Match(v) {
				match = true
				log.WithField("principal", v).Debug("must not include")
			}
		}
		if match {
			log.Debug("mustNotInclude failed")
			return nil, false
		}
	}
	return &auth.AuthContext{
		Parent:           actx,
		RemovePrincipals: removePrincipals,
		Authorizer:       pf.Name(),
	}, true
}

func (pf *PrincipalFilter) Description() string {
	return ""
}

func (pf *PrincipalFilter) Name() string {
	return pf.config.Name
}

func NewPrincipalFilter(config PrincipalFilterConfig) (auth.Authorizer, error) {
	var compileError error
	compile := func(pattern string) glob.Glob {
		glob, err := glob.Compile(pattern)
		if err != nil && compileError == nil {
			compileError = errors.Wrapf(err, "cannot compile %q", pattern)
		}
		return glob
	}
	r := &PrincipalFilter{
		config: config,
		log:    Log.WithField("name", config.Name),
	}
	if config.FilterIncludePrincipalsGlob != "" {
		r.filterInclude = compile(config.FilterIncludePrincipalsGlob)
	}
	if config.FilterExcludePrincipalsGlob != "" {
		r.filterExclude = compile(config.FilterExcludePrincipalsGlob)
	}
	if config.MustIncludePrincipalGlob != "" {
		r.mustInclude = compile(config.MustIncludePrincipalGlob)
	}
	if config.MustNotIncludePrincipalGlob != "" {
		r.mustNotInclude = compile(config.MustNotIncludePrincipalGlob)
	}
	if compileError != nil {
		return nil, compileError
	}

	return r, nil
}
