export declare class Witness {
    private authID;
    private mdDoc;
    private subjectSig;
    private attributes;
    private sig;
    constructor(authID: any, mdDoc: string, subjectSig: string);
    constructor(authID: any, mdDoc: string, subjectSig: string, attributes: object, sig: string);
    sign(attributes: object): Promise<void>;
    verify(): Promise<object>;
    getAttributes(): object;
    getSig(): string;
    static fromSig(authID: any, mdDoc: string, subjectSig: string, sig: string): Witness;
}
