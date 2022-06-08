package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.ArticleDto
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper
interface ArticleMapper {
    fun map(article: ArticleDto): io.icure.kraken.client.models.ArticleDto
    fun map(article: io.icure.kraken.client.models.ArticleDto): ArticleDto
}

object ArticleMapperFactory {
    val instance = Mappers.getMapper(ArticleMapper::class.java)
}
