import { Witness } from "./witness";
export declare class AuthIDMDSig {
    private authID;
    private mdDoc;
    private attributes;
    private sig;
    private witnesses;
    constructor(authID: any, mdDoc: string);
    constructor(authID: any, mdDoc: string, attributes: object, sig: string, witnesses: Array<string>);
    getAttributes(): object;
    getFieldIds(): Array<string>;
    getWitnessFieldIds(): Array<string>;
    getMdDoc(): string;
    sign(attributes: object): Promise<void>;
    verify(): Promise<object>;
    witness(witnessAttributes: object): Promise<void>;
    getWitnesses(): Array<Witness>;
    encode(): string;
    static fromEncoded(authID: any, encoded: string): AuthIDMDSig;
}
