package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.CodeStub
import io.icure.kraken.client.models.CodeStubDto
import org.mapstruct.Mapper

@Mapper
abstract class CodeStubMapper {
    fun map(codeStub: CodeStub): CodeStubDto = CodeStubDto(
        id = codeStub.id,
        context = codeStub.context,
        type = codeStub.type,
        code = codeStub.code,
        version = codeStub.version,
        label = codeStub.label
    )
    fun map(codeStubDto: CodeStubDto): CodeStub = CodeStub(
        id = codeStubDto.id ?: "${codeStubDto.type}|${codeStubDto.code}|${codeStubDto.version}",
        context = codeStubDto.context,
        type = codeStubDto.type,
        code = codeStubDto.code,
        version = codeStubDto.version,
        label = codeStubDto.label
    )
}

object CodeStubMapperFactory {
    val instance = CodeStubMapperImpl()
}
