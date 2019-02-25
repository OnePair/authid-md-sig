import { Witness } from "./witness";

import cheerio from "cheerio";
import crypto from "crypto";
import JWT from "jsonwebtoken";

export class AuthIDMDSig {
  private authID: any; // The AuthID provider

  private mdDoc: string; // The markdown document
  private attributes: object;
  private sig: string;
  private witnesses: Array<string>;


  constructor(authID: any, mdDoc: string);
  constructor(authID: any, mdDoc: string, attributes: object,
    sig: string, witnesses: Array<string>)
  constructor(authID: any, mdDoc: string, attributes?: object,
    sig?: string, witnesses?: Array<string>) {
    this.authID = authID;
    this.mdDoc = mdDoc;
    this.attributes = attributes || null;
    this.sig = sig || null;
    this.witnesses = witnesses || [];
  }

  public getAttributes(): object {
    return this.attributes;
  }

  public getFieldIds(): Array<string> {
    let $ = cheerio.load(this.mdDoc);
    let fieldIds: string[] = [];

    let inputs = $(":input");

    let input = inputs;

    let exit = false;

    while (input.attr("id") != undefined) {
      if (input.attr("class") == "main-subject")
        fieldIds.push(input.attr("id"));
      input = input.next();
    }

    return fieldIds;
  }

  public getWitnessFieldIds(): Array<string> {
    let $ = cheerio.load(this.mdDoc);
    let fieldIds: string[] = [];

    let inputs = $(":input");

    let input = inputs;

    let exit = false;

    while (input.attr("id") != undefined) {
      if (input.attr("class") == "witness")
        fieldIds.push(input.attr("id"));
      input = input.next();
    }

    return fieldIds;
  }

  public getMdDoc(): string {
    return this.mdDoc;
  }

  public sign(attributes: object): Promise<void> {
    return new Promise(async (onSuccess: Function, onError: Function) => {
      try {
        // 1) Hash the mdDoc
        let docHash = crypto.createHash("sha256").update(this.mdDoc).digest("hex");

        // 2) Create json
        let claims = {
          docHash: docHash,
          attributes: attributes
        }

        // 3) Sign
        let sig = await this.authID.createJwt(claims, null);
        this.attributes = attributes;
        this.sig = sig["jwt"];

        onSuccess();
      } catch (err) {
        onError(err);
      }
    });
  }

  /*
  * Verify the signed doc and return the signer id.
  */
  public verify(): Promise<object> {
    return new Promise(async (onSuccess: Function, onError: Function) => {
      try {
        // 1) Hash the mdDoc
        let docHash = crypto.createHash("sha256").update(this.mdDoc).digest("hex");

        // 2) Decode the signature
        let signedValues = JWT.decode(this.sig);

        // 3) Verify the dochash against the one in the signature
        if (docHash != signedValues["docHash"])
          throw new Error("Document hash does not match!");

        // 4) Get the signer's id
        let issuer = signedValues["issuer"];
        let issuerId;

        if (issuer["type"] == "processor") {
          let processor = JWT.decode(issuer["processor"]);
          let processorIssuer = processor["issuer"];

          if ("did" in processorIssuer)
            issuerId = processorIssuer["did"];
          else
            issuerId = processorIssuer["id"];
        } else {
          issuerId = issuer["did"]
        }

        let verified = await this.authID.verifyJwt(this.sig, issuerId);

        let verificationResult = { valid: verified["valid"], id: issuerId };

        onSuccess(verificationResult);

      } catch (err) {
        onError(err);
      }
    });
  }

  public witness(witnessAttributes: object): Promise<void> {
    return new Promise(async (onSuccess: Function, onError: Function) => {
      try {
        let witness = new Witness(this.authID, this.mdDoc, this.sig);

        await witness.sign(witnessAttributes);
        this.witnesses.push(witness.getSig());

        onSuccess();
      } catch (err) {
        onError(err);
      }
    });
  }

  public getWitnesses(): Array<Witness> {
    let decodedWitnesses = [];

    for (var i in this.witnesses) {
      decodedWitnesses.push(Witness.fromSig(this.authID, this.mdDoc,
        this.sig, this.witnesses[i]))
    }
    return decodedWitnesses;
  }

  public encode(): string {
    let docJson = {
      mdDoc: this.mdDoc,
      sig: this.sig,
      witnesses: this.witnesses
    };

    return Buffer.from(JSON.stringify(docJson)).toString("base64");
  }

  public static fromEncoded(authID: any, encoded: string): AuthIDMDSig {
    //throw new Error("Not implemented yet!");
    let docJson = JSON.parse(Buffer.from(encoded, "base64").toString());

    let attributes = JWT.decode(docJson["sig"])["attributes"];

    return new AuthIDMDSig(authID, docJson["mdDoc"], attributes, docJson["sig"], docJson["witnesses"]);
  }
}
