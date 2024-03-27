import {
  validateIAMPolicy,
  readJsonFromFile,
  checkForSingleAsterisk,
} from "../app.ts";
import { IAMPolicy } from "../app.ts";

describe("IAM Role Policy Validation", () => {
  test("Valid policy with basic structure", () => {
    const policy = {
      PolicyName: "test",
      PolicyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: ["s3:ListBucket"],
            Resource: "arn:aws:s3:::my-bucket",
          },
        ],
      },
    };
    expect(() => validateIAMPolicy(policy)).not.toThrow();
  });
  describe("Mandatory Field Tests", () => {
    test("Missing PolicyDocument", () => {
      const policy = {
        PolicyName: "test",
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).toThrow(Error);
    });
    test("Missing Version", () => {
      const policy = {
        PolicyName: "test",
        PolicyDocument: {
          Statement: [{}],
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).toThrow(Error);
    });
    test("Missing Statement", () => {
      const policy = {
        PolicyName: "test",
        PolicyDocument: {
          Version: "2012-10-17",
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).toThrow(Error);
    });
    describe("PolicyName Validation", () => {
      test("Missing PolicyName", () => {
        const policy = {
          PolicyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: ["s3:ListBucket"],
                Resource: "arn:aws:s3:::my-bucket",
              },
            ],
          },
        } as IAMPolicy;
        expect(() => validateIAMPolicy(policy)).toThrow(Error);
      });
      test("PolicyName with invalid type", () => {
        const policy = {
          PolicyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: ["s3:ListBucket"],
                Resource: "arn:aws:s3:::my-bucket",
              },
            ],
          },
          PolicyName: 123 as any,
        } as IAMPolicy;
        expect(() => validateIAMPolicy(policy)).toThrow(Error);
      });

      test("PolicyName with invalid characters", () => {
        const policy = {
          PolicyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: ["s3:ListBucket"],
                Resource: "arn:aws:s3:::my-bucket",
              },
            ],
          },
          PolicyName: "WrongPolicy#",
        } as IAMPolicy;
        expect(() => validateIAMPolicy(policy)).toThrow(Error);
      });

      test("Empty PolicyName", () => {
        const policy = {
          PolicyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: ["s3:ListBucket"],
                Resource: "arn:aws:s3:::my-bucket",
              },
            ],
          },
          PolicyName: "",
        } as IAMPolicy;
        expect(() => validateIAMPolicy(policy)).toThrow(Error);
      });

      test("Valid PolicyName", () => {
        const policy = {
          PolicyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: ["s3:ListBucket"],
                Resource: "arn:aws:s3:::my-bucket",
              },
            ],
          },
          PolicyName: "VaLiD-policy123",
        } as IAMPolicy;
        expect(() => validateIAMPolicy(policy)).not.toThrow();
      });
    });
  });
  describe("Statement Level Tests", () => {
    test("Missing Effect", () => {
      const policy = {
        PolicyName: "test",
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Action: ["s3:ListBucket"],
              Resource: "arn:aws:s3:::my-bucket",
            },
          ],
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).toThrow(Error);
    });
    test("Invalid Effect", () => {
      const policy = {
        PolicyName: "test",
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Permit",
              Action: ["s3:ListBucket"],
              Resource: "arn:aws:s3:::my-bucket",
            },
          ],
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).toThrow(Error);
    });

    test("Missing Action", () => {
      const policy = {
        PolicyName: "test",
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Resource: "arn:aws:s3:::my-bucket",
            },
          ],
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).toThrow(Error);
    });

    test("Missing Resource", () => {
      const policy = {
        PolicyName: "test",
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: ["s3:ListBucket"],
            },
          ],
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).toThrow(Error);
    });

    test("Single Asterisk Resource", () => {
      const policy = {
        PolicyName: "test",
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: ["s3:ListBucket"],
              Resource: "*",
            },
          ],
        },
      } as IAMPolicy;
      expect(checkForSingleAsterisk(policy)).toBe(false);
    });
  });
  describe("Advanced / Edge Cases ", () => {
    test("Multiple Statements (Mix of Valid and Invalid)", () => {
      const policy = {
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: ["s3:ListBucket"],
              Resource: "arn:aws:s3:::my-bucket",
            },
            { Effect: "Allow", Action: "s3:GetObject", Resource: "*" },
          ],
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).toThrow(Error);
    });

    test("Multiple Statements Valid", () => {
      const policy = {
        PolicyName: "root",
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: ["s3:ListBucket"],
              Resource: "arn:aws:s3:::my-bucket",
            },
            {
              Effect: "Allow",
              Action: ["s3:GetObject"],
              Resource: "arn:aws:s3:::my-bucket",
            },
            {
              Effect: "Deny",
              Action: ["s3:GetObject"],
              Resource: "arn:aws:s3:::my-bucket",
            },
          ],
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).not.toThrow();
    });

    test("Nested Resources", () => {
      const policy = {
        PolicyName: "root",
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: ["s3:GetObject"],
              Resource: "arn:aws:s3:::my-bucket/folder/*",
            },
          ],
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).not.toThrow();
    });

    test("Case Sensitivity (Effect)", () => {
      const policy = {
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "allow",
              Action: ["s3:ListBucket"],
              Resource: "arn:aws:s3:::my-bucket",
            },
          ],
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).toThrow(Error);
    });

    test("Long Resource ARNs", () => {
      const longResource =
        "arn:aws:s3:::my-bucket/" + "long".repeat(200) + "/object";

      const policy = {
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: ["s3:GetObject"],
              Resource: longResource,
            },
          ],
        },
      } as IAMPolicy;
      expect(() => validateIAMPolicy(policy)).toThrow(Error);
    });
  });
});
