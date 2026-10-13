from src.database.session import session_scope
from src.attack_data.loader import load_all
from src.analysis.coverage_analyzer import populate_technique_coverage
from src.config_loader import load_config
from src.parser.mappings_io import load_mappings

with session_scope() as s:
    load_all(s)
    config = load_config('config.yaml')
    rules = load_mappings('data/attack_mappings.csv')
    populate_technique_coverage(s, rules, config)
    print("Done!")
