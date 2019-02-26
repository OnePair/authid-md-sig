import crypto from "crypto";
import JWT from "jsonwebtoken";

export class Witness {
  private authID: any;

  private mdDoc: string;
  private subjectSig: string;
  private attributes: object;
  private sig: string;

  constructor(authID: any, mdDoc: string, subjectSig: string);
  constructor(authID: any, mdDoc: string, subjectSig: string,
    attributes: object, sig: string);
  constructor(authID: any, mdDoc: string, subjectSig: string,
    attributes?: object, sig?: string) {
    this.authID = authID;
    this.mdDoc = mdDoc;
    this.subjectSig = subjectSig;
    this.attributes = attributes || null;
    this.sig = sig || null;
  }

  public sign(attributes: object): Promise<void> {
    return new Promise(async (onSuccess: Function, onError: Function) => {
      try {
        // 1) Hash the md document
        let docHash = crypto.createHash("sha256").update(this.mdDoc).digest("hex");

        // 3) Hash the subject sig
        let subjectSigHash = crypto.createHash("sha256").update(this.subjectSig).digest("hex");

        // 2) Create json
        let claims = {
          docHash: docHash,
          subjectSigHash: subjectSigHash,
          attributes: attributes
        }

        // 3) Sign
        let sig = await this.authID.createJwt(claims, null);
        this.sig = sig["jwt"];

        onSuccess();
      } catch (err) {
        onError(err);
      }
    });
  }

  public verify(): Promise<object> {
    return new Promise(async (onSuccess: Function, onError: Function) => {
      try {

        // 2) Decode the signature
        let signedValues = JWT.decode(this.sig);

        // 3) Verify the doc hash
        let docHash = crypto.createHash("sha256").update(this.mdDoc).digest("hex");

        if (docHash != signedValues["docHash"])
          throw new Error("Document hash does not match!");

        // 4) Verify the subject sig hash
        let subjectSigHash = crypto.createHash("sha256").update(this.subjectSig).digest("hex");

        if (subjectSigHash != signedValues["subjectSigHash"])
          throw new Error("Wrong subject!");

        // *) Get the signer's id
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

  public getAttributes(): object {
    return this.attributes;
  }

  public getSig(): string {
    return this.sig;
  }

  public static fromSig(authID: any, mdDoc: string,
    subjectSig: string, sig: string): Witness {

    let decodedSig = JWT.decode(sig);

    return new Witness(authID, mdDoc, subjectSig,
      decodedSig["attributes"], sig);
  }

}
