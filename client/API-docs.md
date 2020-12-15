# Enarx API description

This document describes the protocol between the various components
of the Enarx project:
- Enarx client
- Enarx keepmgr (Keep Manager)
- Enarx keepldr (Keep Loader)
- Enarx wasmldr (WebAssembly Loader)

The following components present APIs:
- keepmgr*: accessed by the client
- keepldr: accessed by the keepmgr and client (proxied by the keepmgr)
- wasmldr*: accessed by the client

The components with a * are RESTful.

# Objects

### LocalCBorErr
{
	"details": **String**,
}
### CommsComplete
**CommsComplete** is a signal that all communications are complete in a protocol set.

NOTE: I'm not sure how to describe this object, which is a Rust Enum.

TBD: needed or not?
{
	Success,
	Failure,	
}

### ContractList
**ContractList** is a list of **KeepContract**s. 

NOTE: I'm not sure how to describe this object, which is a Vec of KeepContract
objects.

### KeepContract
**KeepContract** is a representation of a contract that can be redeemed as a **Keep**.

pub struct KeepContract {
    "keepmgr": KeepMgr,
    "backend": Backend,
    "uuid": **uuid::Uuid**,
}

### KeepMgr
**KeepMgr** represents a Keep Manager running on a host.

{
    "address": **String**,
    "port": **u16**,
}

### Backend
**Backend** represents the type of backend associated with a **KeepContract** and 
associated **Keep**.

NOTE: I'm not sure how to describe this object, which is a Rust Enum.
{
    Nil,
    Sev,
    Sgx,
    Kvm,
}

### KeepList
**KeepList** is a list of **Keep*s.

NOTE: I'm not sure how to describe this object, which is a Vec of KeepContract
objects.

### Keep
**Keep** is an Enarx Keep and associated information.

NOTE: I'm not sure how to describe Options in this object.
{
    "backend": Backend,
    "kuuid": **uuid::Uuid**,
    "state": LoaderState,
    "wasmldr": Option<Wasmldr>,
    "human_readable_info": Option<**String**>,
}

### LoaderState
**LoaderState** is the current state of a **Keep** and its readiness to accept
a **Workload**.

NOTE: I'm not sure how to describe this object, which is a Rust Enum.
{
    Indeterminate,
    Ready,
    Running,
    Shutdown,
    Error,
}


### Wasmldr
**Wasmldr** represents a WebAssembly (Wasm) loader running within a Keep, ready
to accept a **Workload**.
{
    "wasmldr_ipaddr": **String**,
    "wasmldr_port": **u16**,
}

### Workload
**Workload** is a WebAssembly (Wasm) package, sent by a client to a Keep.

NOTE - I'm not sure how to describe Vecs in this object.
{
    "wasm_binary": Vec<**u8**>,
    "human_readable_info": **String**,
}

# Processes
TODO - For all of the below - remove CborReply as irrelevant?
NOTE - all errors are communicated as a **LocalCborError** as the REPLY.

## keepmgr
Each host that is running Enarx Keeps, or ready to run new Enarx Keeps, has a Keep
Manager.  This accepts communications from the **client**, offering contracts to be 
redeemed as new **Keep**s via a **Keep Loader**.  It then proxies communications
between the **client** and the **Keep Loader** until the **client** is ready to 
communicate directly with the **Wasm Loader**.

### /contracts
The contracts endpoint provides information about the contracts available to a client
from the Keep Manager.

POST [empty BODY]
REPLY:
- **ContractList**

### /new_keep/[uuid]
The new_keep endpoint allows the **client** to request the creation of a new **Keep**.
The **Keep Manager** attempts to instantiate a new **Keep Loader**, and passes details
to the **client**
POST: /new_keep/
- BODY: **KeepContract**
REPLY:
 - **Keep**

### /keep/[kuuid]
POST: /keep/[kuuid]/
 - BODY: **Opaque binary data**

Most information is proxied by the Keep Manager opaquely, and the exact protocol
depends on the **Keep** backend.  
TODO - links to backend-specific protocol descriptions.

REPLY: 
 - **Opaque binary data**
  
The **Keep Loader** *may* choose to signal to the **Keep Manager** that the 
communication is complete with a **CommsComplete**.  If this message is received by
the **Keep Manager**, it *must* forward it to the **client**.

OR
REPLY: 
 - **CommsComplete**
  
## keepldr
The **Keep Loader** sets up the **Keep**, managing attestation and other configuration
requirements.

### [tbd]/[uuid] 
(Over a UNIX domain socket)
This endpoint allows the **Keep Manager** to communicate with the **Keep Loader**.

## wasmldr
Each **Keep** has a **Wasm Loader**, instantiated after attestation is complete.  The
**client** associated with the **Keep** communicates with the **Wasm Loader** to 
provide a workload which is then loaded and run in the **Keep**.

### /workload
The workload endpoint allows the **client** to send a WebAssembly workload to the 
**Wasm Loader** for loading and execution.

POST: /workload
 - BODY: **Workload**
 
REPLY: 
- *TBD*
