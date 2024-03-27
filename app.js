"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkForSingleAsterisk = exports.validateIAMPolicy = exports.readJsonFromFile = void 0;
var fs = require("fs");
var path = require("path");
function readJsonFromFile(filePath) {
    var extension = path.extname(filePath).toLowerCase();
    if (extension !== ".json") {
        console.error("Error: Wrong file extension");
        process.exit(1);
    }
    try {
        return fs.readFileSync(filePath, "utf-8");
    }
    catch (error) {
        if (error.code === "ENOENT") {
            console.error("Error: No such file or directory.");
            process.exit(1);
        }
        else {
            console.error("Error reading file:", error);
            throw error;
            process.exit(1);
        }
    }
}
exports.readJsonFromFile = readJsonFromFile;
function validateIAMPolicy(policy) {
    if (!policy.PolicyDocument || typeof policy.PolicyDocument !== "object") {
        throw new Error("PolicyDocument is missing or invalid.");
    }
    if (!policy.PolicyName || typeof policy.PolicyName !== "string") {
        throw new Error("PolicyName is missing or invalid.");
    }
    if (!/^[a-zA-Z0-9+=,.@-]+$/.test(policy.PolicyName)) {
        throw new Error("PolicyName does not match the required pattern.");
    }
    if (policy.PolicyName.length < 1 || policy.PolicyName.length > 128) {
        throw new Error("PolicyName length is outside the allowed range (1-128).");
    }
    if (!policy.PolicyDocument.Version ||
        policy.PolicyDocument.Version !== "2012-10-17") {
        throw new Error("Invalid or missing Version in PolicyDocument.");
    }
    if (!policy.PolicyDocument.Statement ||
        !Array.isArray(policy.PolicyDocument.Statement) ||
        policy.PolicyDocument.Statement.length === 0) {
        throw new Error("Statement array is either missing or empty.");
    }
    for (var _i = 0, _a = policy.PolicyDocument.Statement; _i < _a.length; _i++) {
        var statement = _a[_i];
        if (!statement.Effect ||
            (statement.Effect !== "Allow" && statement.Effect !== "Deny")) {
            throw new Error("Invalid or missing Effect in Statement.");
        }
        if (!statement.Action ||
            !Array.isArray(statement.Action) ||
            statement.Action.length === 0) {
            throw new Error("Action array is missing or empty in Statement.");
        }
        if (statement.Resource.trim() !== "*") {
            if (!statement.Resource || typeof statement.Resource !== "string") {
                throw new Error("Invalid or missing Resource in Statement.");
            }
            if (!statement.Resource.includes(":aws:")) {
                throw new Error("Resource field must include 'aws' partition.");
            }
            if (statement.Resource.length > 200) {
                throw new Error("Resource field exceeds maximum allowed length (200).");
            }
        }
    }
}
exports.validateIAMPolicy = validateIAMPolicy;
function checkForSingleAsterisk(policy) {
    for (var _i = 0, _a = policy.PolicyDocument.Statement; _i < _a.length; _i++) {
        var statement = _a[_i];
        if (statement.Resource === "*") {
            return false;
        }
    }
    return true;
}
exports.checkForSingleAsterisk = checkForSingleAsterisk;
if (require.main === module) {
    var args = process.argv.slice(2);
    if (args.length !== 1) {
        console.error("Wrong usage. Usage: node app.js <filename>");
        process.exit(1);
    }
    var filePath = args[0];
    try {
        var policyData = readJsonFromFile(filePath);
        var policy = JSON.parse(policyData);
        validateIAMPolicy(policy);
        console.log(checkForSingleAsterisk(policy));
    }
    catch (error) {
        console.error(error.message);
        process.exit(1);
    }
}
