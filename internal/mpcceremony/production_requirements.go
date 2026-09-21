package mpcceremony

func (d CeremonyDefinition) UsesCoordinatorReplay() bool {
	return d.Schema == DefinitionSchemaV4 || d.Schema == DefinitionSchemaV5
}
