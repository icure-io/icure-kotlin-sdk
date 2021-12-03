package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.applyIf
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.PersonNameDto


fun HealthcarePartyDto.initHcparty() : HealthcarePartyDto {
    return this
        .applyIf({ hcp -> hcp.lastName == null && hcp.hasName(PersonNameDto.Use.official)}) { hcp ->
            hcp.copy(lastName = hcp.findName(PersonNameDto.Use.official)!!.lastName)
        }
        .applyIf({ hcp -> hcp.firstName == null && hcp.hasName(PersonNameDto.Use.official)}) { hcp ->
            hcp.copy(firstName = hcp.findName(PersonNameDto.Use.official)!!.firstNames.firstOrNull())
        }
        .applyIf({ hcp -> hcp.name == null && hcp.hasName(PersonNameDto.Use.official)}) { hcp ->
            hcp.copy(name = hcp.findName(PersonNameDto.Use.official)!!.text)
        }
        .applyIf({ hcp -> (hcp.lastName != null || hcp.name != null) && !hcp.hasName(PersonNameDto.Use.official)}) { hcp ->
            hcp.copy(names = hcp.names + (
                    listOf(PersonNameDto(lastName = hcp.lastName, firstNames = listOfNotNull(hcp.firstName), text = hcp.name, use = PersonNameDto.Use.official))
                    )
            )
        }
}

fun HealthcarePartyDto.hasName(nameUse: PersonNameDto.Use) : Boolean {
    return this.names.find { it.use == nameUse } != null
}

fun HealthcarePartyDto.findName(nameUse: PersonNameDto.Use) : PersonNameDto? {
    return this.names.find { it.use == nameUse }
}