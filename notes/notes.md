22-01-2026

defejsive side - compare defensive frameworks, i.e. network security architectures..., e.g. zero-trust architecutre
- look at aspects of zero trust architecutre and what will/will not work against decentrailed malware, any challenges?


aranya - aranya-daemon/src/daemon.rs line 281 ClientState code


29-01-2026


        struct Envelope {
            payload bytes
        }
        command Foo {
            fields {}
            seal {
                return Envelope {
                    payload: serialize(this),
                }
            }
            open {
                return deserialize(envelope.payload)
            }
        }

        