package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.ArticleDto
import org.mapstruct.Mapper

@Mapper
interface ArticleMapper {
    fun map(article: ArticleDto): io.icure.kraken.client.models.ArticleDto
    fun map(article: io.icure.kraken.client.models.ArticleDto): ArticleDto
}

object ArticleMapperFactory {
    val instance = ArticleMapperImpl()
}
