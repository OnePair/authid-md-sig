# authid-md-sig

> A markdown electronic signatures reference implementation built in typescript.

## Install and Build

1. ```npm install```
2. ```npm run build```

## Usage

* Sign and verify.
    1. Sign a markdown document.
        ```js
        import { AuthIDMDSig } from "authid-md-sig"

        let doc = new AuthIDMDSig(authID, mdDoc);

        // Get the required fields
        let fieldIds = doc.getFieldIds();

        await doc.sign("<attributes>");

        // Encode
        console.log(encode);

        ```
    2. Verify a signed markdown document
        ```js
        doc.verify().then((verified) => {
            console.log("verified:", verified);
        }).catch((err) => {
            console.log("Doc is not valid");
        });
        ```
