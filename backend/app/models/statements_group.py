from enum import Enum


class StatementsGroup(str, Enum):
    no_clustering = "no_clustering"
    affected_component_manager = "affected_component_manager"
    cwe_type = "cwe_type"
    attack_vector_av = "attack_vector_av"
    attack_vector_ac = "attack_vector_ac"
    attack_vector_au = "attack_vector_au"
    attack_vector_c = "attack_vector_c"
    attack_vector_i = "attack_vector_i"
    attack_vector_a = "attack_vector_a"
    reachable_code = "reachable_code"
