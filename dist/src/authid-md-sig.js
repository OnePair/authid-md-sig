"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var witness_1 = require("./witness");
var cheerio_1 = __importDefault(require("cheerio"));
var crypto = __importStar(require("crypto"));
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
var AuthIDMDSig = /** @class */ (function () {
    function AuthIDMDSig(authID, mdDoc, attributes, sig, witnesses) {
        this.authID = authID;
        this.mdDoc = mdDoc;
        this.attributes = attributes || null;
        this.sig = sig || null;
        this.witnesses = witnesses || [];
    }
    AuthIDMDSig.prototype.getAttributes = function () {
        return this.attributes;
    };
    AuthIDMDSig.prototype.getFieldIds = function () {
        var $ = cheerio_1.default.load(this.mdDoc);
        var fieldIds = [];
        var inputs = $(":input");
        var input = inputs;
        var exit = false;
        while (input.attr("id") != undefined) {
            if (input.attr("class") == "main-subject")
                fieldIds.push(input.attr("id"));
            input = input.next();
        }
        return fieldIds;
    };
    AuthIDMDSig.prototype.getWitnessFieldIds = function () {
        var $ = cheerio_1.default.load(this.mdDoc);
        var fieldIds = [];
        var inputs = $(":input");
        var input = inputs;
        var exit = false;
        while (input.attr("id") != undefined) {
            if (input.attr("class") == "witness")
                fieldIds.push(input.attr("id"));
            input = input.next();
        }
        return fieldIds;
    };
    AuthIDMDSig.prototype.getMdDoc = function () {
        return this.mdDoc;
    };
    AuthIDMDSig.prototype.sign = function (attributes) {
        var _this = this;
        return new Promise(function (onSuccess, onError) { return __awaiter(_this, void 0, void 0, function () {
            var docHash, claims, sig, err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        docHash = crypto.createHash("sha256").update(this.mdDoc).digest("hex");
                        claims = {
                            docHash: docHash,
                            attributes: attributes
                        };
                        return [4 /*yield*/, this.authID.createJwt(claims, null)];
                    case 1:
                        sig = _a.sent();
                        this.attributes = attributes;
                        this.sig = sig["jwt"];
                        onSuccess();
                        return [3 /*break*/, 3];
                    case 2:
                        err_1 = _a.sent();
                        onError(err_1);
                        return [3 /*break*/, 3];
                    case 3: return [2 /*return*/];
                }
            });
        }); });
    };
    /*
    * Verify the signed doc and return the signer id.
    */
    AuthIDMDSig.prototype.verify = function () {
        var _this = this;
        return new Promise(function (onSuccess, onError) { return __awaiter(_this, void 0, void 0, function () {
            var docHash, signedValues, issuerId, issuer, processor, processorIssuer, verified, verificationResult, err_2;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        docHash = crypto.createHash("sha256").update(this.mdDoc).digest("hex");
                        signedValues = jsonwebtoken_1.default.decode(this.sig);
                        // 3) Verify the dochash against the one in the signature
                        if (docHash != signedValues["docHash"])
                            throw new Error("Document hash does not match!");
                        issuerId = void 0;
                        if ("name" in signedValues)
                            issuerId = signedValues["name"];
                        else { // The issuer is just a DID
                            issuer = signedValues["issuer"];
                            if (issuer["type"] == "processor") {
                                processor = jsonwebtoken_1.default.decode(issuer["processor"]);
                                processorIssuer = processor["issuer"];
                                if ("did" in processorIssuer)
                                    issuerId = processorIssuer["did"];
                                else
                                    issuerId = processorIssuer["id"];
                            }
                            else {
                                issuerId = issuer["did"];
                            }
                        }
                        return [4 /*yield*/, this.authID.verifyJwt(this.sig, issuerId)];
                    case 1:
                        verified = _a.sent();
                        verificationResult = { valid: verified["valid"], id: issuerId };
                        onSuccess(verificationResult);
                        return [3 /*break*/, 3];
                    case 2:
                        err_2 = _a.sent();
                        onError(err_2);
                        return [3 /*break*/, 3];
                    case 3: return [2 /*return*/];
                }
            });
        }); });
    };
    AuthIDMDSig.prototype.witness = function (witnessAttributes) {
        var _this = this;
        return new Promise(function (onSuccess, onError) { return __awaiter(_this, void 0, void 0, function () {
            var witness, err_3;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        witness = new witness_1.Witness(this.authID, this.mdDoc, this.sig);
                        return [4 /*yield*/, witness.sign(witnessAttributes)];
                    case 1:
                        _a.sent();
                        this.witnesses.push(witness.getSig());
                        onSuccess();
                        return [3 /*break*/, 3];
                    case 2:
                        err_3 = _a.sent();
                        onError(err_3);
                        return [3 /*break*/, 3];
                    case 3: return [2 /*return*/];
                }
            });
        }); });
    };
    AuthIDMDSig.prototype.getWitnesses = function () {
        var decodedWitnesses = [];
        for (var i in this.witnesses) {
            decodedWitnesses.push(witness_1.Witness.fromSig(this.authID, this.mdDoc, this.sig, this.witnesses[i]));
        }
        return decodedWitnesses;
    };
    AuthIDMDSig.prototype.encode = function () {
        var docJson = {
            mdDoc: this.mdDoc,
            sig: this.sig,
            witnesses: this.witnesses
        };
        return Buffer.from(JSON.stringify(docJson)).toString("base64");
    };
    AuthIDMDSig.fromEncoded = function (authID, encoded) {
        //throw new Error("Not implemented yet!");
        var docJson = JSON.parse(Buffer.from(encoded, "base64").toString());
        var attributes = jsonwebtoken_1.default.decode(docJson["sig"])["attributes"];
        return new AuthIDMDSig(authID, docJson["mdDoc"], attributes, docJson["sig"], docJson["witnesses"]);
    };
    return AuthIDMDSig;
}());
exports.AuthIDMDSig = AuthIDMDSig;
