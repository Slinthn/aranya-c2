---
policy-version: 2
---

```policy
// use afc
// use crypto
use device
// use envelope
// use idam
use perspective
use myffi

enum UserType {
    OPERATOR,
    USER
}

struct User {
    type enum UserType
}

// function do_seal(payload bytes) struct Envelope {
//     // let signed = cryto::sign()
    
//     return envelope::new(
//         perspective::head_id(),
//         device::current_device_id()
//     )
// }

struct Envelope {
    parent_id id,
    author_id id,
    command_id id,
    payload bytes,
    signature bytes
}

command Init {
    fields {
        a int,
    }

    attributes {
        init: true
    }

    seal {
        let parent_id = perspective::head_id()

        let test = myffi::haha()

        return Envelope {
            parent_id: parent_id,
            author_id: parent_id,
            command_id: test,
            payload: serialize(this),
            signature: serialize(this),
        }
    }
    open {
        return deserialize(envelope.payload)
    }

    policy {
        finish {
        }
    }
}

action init() {
    publish Init {
        a: 5
    }
}

fact Stuff[a int]=>{x int}

effect StuffHappened {
    a int,
    x int,
}

command Hello {
    fields {
        stuff_key int,
        stuff_value int
    }

    attributes {
        priority: 1
    }

    seal {
        let parent_id = perspective::head_id()
        let device_id = parent_id
        // let device_id = device::current_device_id()

        return Envelope {
            parent_id: parent_id,
            author_id: device_id,
            command_id: myffi::haha(),
            payload: serialize(this),
            signature: serialize(this),
        }
    }
    open {
        return deserialize(envelope.payload)
    }

    policy {
        finish {
            create Stuff[a: this.stuff_key] => {x: this.stuff_value}
            emit StuffHappened{a: this.stuff_key, x: this.stuff_value}
        }
    }
}


command Hey {
    fields {
        stuff_key int,
        stuff_value int
    }

    attributes {
        priority: 2
    }

    seal {
        let parent_id = perspective::head_id()
        let device_id = parent_id
        // let device_id = device::current_device_id()

        return Envelope {
            parent_id: parent_id,
            author_id: device_id,
            command_id: myffi::haha(),
            payload: serialize(this),
            signature: serialize(this),
        }
    }
    open {
        return deserialize(envelope.payload)
    }

    policy {
        finish {
            create Stuff[a: this.stuff_key] => {x: this.stuff_value}
            emit StuffHappened{a: this.stuff_key, x: this.stuff_value}
        }
    }
}


action hello() {
    publish Hello {
        stuff_key: 5,
        stuff_value: 10
    }
}

action hey() {
    publish Hey {
        stuff_key: 6,
        stuff_value: 7
    }
}

// command NetworkCreateCommand {

// }

action NetworkCreate() {
}

action NetworkJoin() {

}

action ExecuteCommand() {

}
```


// ```policy
// function init() int {
//     return 1
// }
// ```
