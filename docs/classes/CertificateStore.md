[**@opsimathically/certificateauthority**](../README.md)

***

[@opsimathically/certificateauthority](../README.md) / CertificateStore

# Class: CertificateStore

Defined in: [CertificateStore.class.ts:46](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateStore.class.ts#L46)

Simple sqlite based certificate store.  We use this instead of the filesystem to prevent
the potentially overwhelming glut of individual dangling files in the filesystem.

## Constructors

### Constructor

> **new CertificateStore**(`params`): `CertificateStore`

Defined in: [CertificateStore.class.ts:48](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateStore.class.ts#L48)

#### Parameters

##### params

###### file

`string`

#### Returns

`CertificateStore`

## Properties

### db

> **db**: `Database`

Defined in: [CertificateStore.class.ts:47](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateStore.class.ts#L47)

## Methods

### addCAPems()

> **addCAPems**(`params`): `Promise`\<`void`\>

Defined in: [CertificateStore.class.ts:97](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateStore.class.ts#L97)

Add CA pems.

#### Parameters

##### params

`ca_pems_params_t`

#### Returns

`Promise`\<`void`\>

***

### addCASignedPEMSet()

> **addCASignedPEMSet**(`signed_pems`): `Promise`\<`void`\>

Defined in: [CertificateStore.class.ts:171](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateStore.class.ts#L171)

Add a signed PEM set into the database.

#### Parameters

##### signed\_pems

[`ca_signed_https_pems_t`](../type-aliases/ca_signed_https_pems_t.md)

#### Returns

`Promise`\<`void`\>

***

### getCAPems()

> **getCAPems**(`params`): `Promise`\<[`ca_pems_record_t`](../type-aliases/ca_pems_record_t.md)\>

Defined in: [CertificateStore.class.ts:139](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateStore.class.ts#L139)

Get CA pems.

#### Parameters

##### params

###### name

`string`

#### Returns

`Promise`\<[`ca_pems_record_t`](../type-aliases/ca_pems_record_t.md)\>

***

### getCASignedPEMSet()

> **getCASignedPEMSet**(`params`): `Promise`\<[`ca_signed_https_pems_record_t`](../type-aliases/ca_signed_https_pems_record_t.md)\>

Defined in: [CertificateStore.class.ts:214](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateStore.class.ts#L214)

Lookup a signed PEM set.

#### Parameters

##### params

###### ca_pems_sha1

`string`

###### hosts?

`string`[]

###### hosts_unique_sha1?

`string`

#### Returns

`Promise`\<[`ca_signed_https_pems_record_t`](../type-aliases/ca_signed_https_pems_record_t.md)\>

***

### removeCAPems()

> **removeCAPems**(`params`): `Promise`\<`boolean`\>

Defined in: [CertificateStore.class.ts:154](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateStore.class.ts#L154)

Remove CA pems.

#### Parameters

##### params

###### name

`string`

#### Returns

`Promise`\<`boolean`\>

***

### removeCASignedPEMSet()

> **removeCASignedPEMSet**(`params`): `Promise`\<`boolean`\>

Defined in: [CertificateStore.class.ts:259](https://github.com/opsimathically/certificateauthority/blob/38696373b8e07b59fffaf8e84e32119c00d6f73c/src/CertificateStore.class.ts#L259)

Requires one or more unique sha1 constraint to be set.

#### Parameters

##### params

###### ca_pems_sha1

`string`

###### hosts_unique_sha1

`string`

###### pems_sha1

`string`

#### Returns

`Promise`\<`boolean`\>
