package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.CodeStub
import io.icure.kraken.client.models.CodeStubDto
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper
interface CodeStubMapper {
    fun map(codeStub: CodeStub): CodeStubDto
    fun map(codeStubDto: CodeStubDto): CodeStub
}


object CodeStubMapperFactory {
    val instance = Mappers.getMapper(CodeStubMapper::class.java)
}
