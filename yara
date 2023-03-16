rule xenomorph_behavior
{
    meta:
        description = "Detects Xenomorph's behavior of collecting PII and targeting specific countries and institutions"
author = "Fevar54"
        date = "2023-03-16"
    strings:
        $piis = /([A-Za-z0-9\.\-\_]+@[A-Za-z0-9\.\-\_]+)/
        $countries = /Spain|Portugal|Italy|Belgium|Canada/
        $institutions = /institution_1|institution_2|institution_3|wallet_1|wallet_2|wallet_3/
    condition:
        ($piis or $countries or $institutions) and
        (all of ($piis, $countries, $institutions))
}
