[**@opsimathically/certificateauthority**](../README.md)

***

[@opsimathically/certificateauthority](../README.md) / CertificateAuthority

# Class: CertificateAuthority

Defined in: [CertificateAuthority.class.ts:56](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateAuthority.class.ts#L56)

## Constructors

### Constructor

> **new CertificateAuthority**(): `CertificateAuthority`

Defined in: [CertificateAuthority.class.ts:64](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateAuthority.class.ts#L64)

#### Returns

`CertificateAuthority`

## Properties

### ca\_loaded\_ctx

> **ca\_loaded\_ctx**: [`ca_loaded_context_t`](../type-aliases/ca_loaded_context_t.md)

Defined in: [CertificateAuthority.class.ts:61](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateAuthority.class.ts#L61)

***

### ca\_store

> **ca\_store**: [`CertificateStore`](CertificateStore.md)

Defined in: [CertificateAuthority.class.ts:58](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateAuthority.class.ts#L58)

## Methods

### generateServerCertificateAndKeysPEMSet()

> **generateServerCertificateAndKeysPEMSet**(`hosts`): `Promise`\<[`ca_signed_https_pems_t`](../type-aliases/ca_signed_https_pems_t.md)\>

Defined in: [CertificateAuthority.class.ts:270](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateAuthority.class.ts#L270)

This method is used to generate cert/priv/public key usable for a
nodejs https server (MITM server)

#### Parameters

##### hosts

`string`[]

#### Returns

`Promise`\<[`ca_signed_https_pems_t`](../type-aliases/ca_signed_https_pems_t.md)\>

***

### init()

> **init**(`params`): `Promise`\<`boolean`\>

Defined in: [CertificateAuthority.class.ts:67](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateAuthority.class.ts#L67)

#### Parameters

##### params

###### ca_attrs?

`CertificateField`[]

###### description

`string`

###### file

`string`

###### name

`string`

#### Returns

`Promise`\<`boolean`\>

***

### randomSerialNumber()

> **randomSerialNumber**(): `string`

Defined in: [CertificateAuthority.class.ts:482](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateAuthority.class.ts#L482)

#### Returns

`string`
