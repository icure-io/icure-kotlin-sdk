package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.ArticleApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.fromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.ArticleDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun ArticleDto.initDelegations(user: UserDto, config: CryptoConfig<ArticleDto>): ArticleDto {
    val delegations =  (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf())
    val ek = UUID.randomUUID().toString()
    val sfk = UUID.randomUUID().toString()
    return this.copy(
        responsible = user.healthcarePartyId!!,
        author = user.id,
        delegations = (delegations + user.healthcarePartyId!!).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    listOf(), user.healthcarePartyId, d, config.crypto.encryptKeyForHcp(user.healthcarePartyId, d, this.id, sfk),
                ),
            ))
        },
        encryptionKeys = (delegations + user.healthcarePartyId!!).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    listOf(), user.healthcarePartyId, d, config.crypto.encryptKeyForHcp(user.healthcarePartyId, d, this.id, ek),
                ),
            ))
        },
    )
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ArticleApi.createArticle(user: UserDto, article: ArticleDto, config: CryptoConfig<ArticleDto>) =
    this.createArticle(
        config.encryptArticle(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            article
        )
    )?.let { config.decryptArticle(user.healthcarePartyId!!, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ArticleApi.getArticle(user: UserDto, articleId: String, config: CryptoConfig<ArticleDto>): ArticleDto?  {
    return this.getArticle(articleId)?.let { config.decryptArticle(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ArticleApi.getArticles(user: UserDto, config: CryptoConfig<ArticleDto>) : List<ArticleDto>?  {
    return this.getArticles()?.map { config.decryptArticle(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ArticleApi.modifyArticle(user: UserDto, article: ArticleDto, config: CryptoConfig<ArticleDto>) : ArticleDto?  {
    return this.modifyArticle(
        config.encryptArticle(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            article
        )
    )?.let { config.decryptArticle(user.healthcarePartyId!!, it) }
}

suspend fun CryptoConfig<ArticleDto>.encryptArticle(myId: String, delegations: Set<String>, article: ArticleDto): io.icure.kraken.client.models.ArticleDto {
    return if (article.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        article
    } else {
        val secret = UUID.randomUUID().toString()
        article.copy(encryptionKeys = (delegations + myId).fold(article.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptKeyForHcp(myId, d, article.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
            aesKey.replace(
                "-",
                ""
            ).fromHexString()
        } ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedArticle, marshalledData) = this.marshaller(p)
        ArticleMapperFactory.instance.map(sanitizedArticle.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key))))
    }
}

suspend fun CryptoConfig<ArticleDto>.decryptArticle(myId: String, article: io.icure.kraken.client.models.ArticleDto): ArticleDto = ArticleMapperFactory.instance.map(article).let { p ->
    val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
        aesKey.replace(
            "-",
            ""
        ).fromHexString()
    } ?: throw IllegalArgumentException("No encryption key for user")
    this.unmarshaller(p, decryptAES(data = Base64.getDecoder().decode(p.encryptedSelf), key = key))
}

@Mapper
interface ArticleMapper {
    fun map(article: ArticleDto): io.icure.kraken.client.models.ArticleDto
    fun map(article: io.icure.kraken.client.models.ArticleDto): ArticleDto
}

object ArticleMapperFactory {
    val instance = Mappers.getMapper(ArticleMapper::class.java)
}