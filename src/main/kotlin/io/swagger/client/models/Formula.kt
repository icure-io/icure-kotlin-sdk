/**
 * iCure Cloud API Documentation
 * Spring shop sample application
 *
 * OpenAPI spec version: v0.0.1
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */
package io.swagger.client.models


/**
 * 
 * @param value 
 * @param lifecycle 
 */
data class Formula (

    val value: kotlin.String? = null,
    val lifecycle: Formula.Lifecycle? = null
) {
    /**
    * 
    * Values: onCreate,onLoad,onChange,onSave,onDestroy,onLoadPropertiesEditor
    */
    enum class Lifecycle(val value: kotlin.String){
        onCreate("OnCreate"),
        onLoad("OnLoad"),
        onChange("OnChange"),
        onSave("OnSave"),
        onDestroy("OnDestroy"),
        onLoadPropertiesEditor("OnLoadPropertiesEditor");
    }
}