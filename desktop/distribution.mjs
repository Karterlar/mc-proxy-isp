const distribution = {"edition":"developer","licenseConfig":{"version":1,"mode":"development"}};
Object.freeze(distribution.licenseConfig.publicKeys ?? {});
Object.freeze(distribution.licenseConfig);
export const DISTRIBUTION = Object.freeze(distribution);
