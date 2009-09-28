using System.Diagnostics;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi.Configuration;
using System;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Text;

namespace Owasp.Esapi
{
    internal class EsapiLoader
    {
        #region Miscellaneous
        /// <summary>
        /// Convert wildcard match string to a regex
        /// </summary>
        /// <param name="wildcardMatch">Wildcard string</param>
        /// <returns></returns>
        internal static Regex WildcardToRegex(string wildcardMatch)
        {
            StringBuilder sbRegex = new StringBuilder();
            sbRegex.Append("^");

            if (!string.IsNullOrEmpty(wildcardMatch)) {
                foreach (char w in wildcardMatch) {
                    if (w == '*') {
                        sbRegex.Append(".*");
                        continue;
                    }
                    if (w == '?') {
                        sbRegex.Append(".");
                        continue;
                    }
                    sbRegex.Append(Regex.Escape(w.ToString()));
                }
            }

            sbRegex.Append("$");

            return new Regex(sbRegex.ToString());
        }
        #endregion

        #region AccessController
        /// <summary>
        /// Load access controller 
        /// </summary>
        /// <param name="controllerConfig">Access controller configuration element</param>
        /// <returns></returns>
        internal static IAccessController LoadAccessController(AccessControllerElement controllerConfig)
        {
            Debug.Assert(controllerConfig != null);

            if (!string.IsNullOrEmpty(controllerConfig.Type)) {
                Type controllerType = Type.GetType(controllerConfig.Type, true);
                return (IAccessController)Activator.CreateInstance(controllerType);
            }

            return new AccessController();
        }
        #endregion

        #region Encoder
        /// <summary>
        /// Load codec instance
        /// </summary>
        /// <param name="encoder">Encoder instance</param>
        /// <param name="codec">Codec type</param>
        /// <returns></returns>
        private static bool LoadCodec(IEncoder encoder,Type codec)
        {
            Debug.Assert(encoder != null);
            Debug.Assert(codec != null);

            bool loaded = false;

            object[] attrs = codec.GetCustomAttributes(typeof(CodecAttribute), false);
            if (attrs != null && attrs.Length > 0) {
                CodecAttribute codecAttr = (CodecAttribute)attrs[0];

                if (codecAttr.AutoLoad) {
                    encoder.AddCodec(codecAttr.Name, (ICodec)Activator.CreateInstance(codec));
                    loaded = true;
                }
            }

            return loaded;
        }
        /// <summary>
        /// Load named codec instance
        /// </summary>
        /// <param name="encoder">Encoder instance</param>
        /// <param name="codec">Codec type</param>
        /// <param name="name">Codec name</param>
        private static void LoadCodec(IEncoder encoder, Type codec, string name)
        {
            Debug.Assert(encoder != null);
            Debug.Assert(codec != null);
            Debug.Assert(name != null);

            encoder.AddCodec(name, (ICodec)Activator.CreateInstance(codec));
        }

        /// <summary>
        /// Load codecs from assembly
        /// </summary>
        /// <param name="encoder"></param>
        /// <param name="assembly"></param>
        /// <param name="typeMatch"></param>
        private static void LoadCodecs(IEncoder encoder, Assembly assembly, Regex typeMatch)
        {
            Debug.Assert(encoder != null);
            Debug.Assert(assembly != null);
            Debug.Assert(typeMatch != null);

            foreach (Type type in assembly.GetTypes()) {
                if (typeMatch.IsMatch(type.FullName)) {
                    LoadCodec(encoder, type);
                }
            }
        }

        /// <summary>
        /// Load encoder element
        /// </summary>
        /// <param name="encoderConfig"></param>
        /// <returns></returns>
        internal static IEncoder LoadEncoder(EncoderElement encoderConfig)
        {
            Debug.Assert(encoderConfig != null);

            // Create encoder
            IEncoder encoder = null;

            if (!string.IsNullOrEmpty(encoderConfig.Type)) {
                Type encoderType = Type.GetType(EsapiConfig.Instance.Encoder.Type, true);
                encoder = (IEncoder)Activator.CreateInstance(encoderType);
            }
            else {
                // Create default encoder and load all local codec defs
                encoder = new Encoder();                
                LoadCodecs(encoder, typeof(Encoder).Assembly, WildcardToRegex(@"Owasp.Esapi.Codecs.*"));
            }
            
            CodecCollection codecs = encoderConfig.Codecs;
            
            // Load codec assemblies
            foreach (AddinAssemblyElement codecAssembly in codecs.Assemblies) {
                try {
                    Assembly assembly = Assembly.Load(codecAssembly.Name);
                    Regex typeMatch = WildcardToRegex(codecAssembly.Types);

                    LoadCodecs(encoder, assembly, typeMatch);
                }
                catch (Exception exp) {
                    Esapi.Logger.Warning(LogLevels.WARN, "Failed to load codec assembly", exp);
                }
            }

            // Specific codecs
            foreach (CodecElement codecElement in codecs) {
                string failMessage = string.Format("Failed to load codec \"{0}\"", codecElement.Name);

                try {
                    Type codecType = Type.GetType(codecElement.Type, true);
                    LoadCodec(encoder, codecType, codecElement.Name);
                }
                catch (Exception exp) {
                    Esapi.Logger.Warning(LogLevels.WARN, failMessage, exp);
                }
            }

            return encoder;
        }
        #endregion

        #region Encryptor
        /// <summary>
        /// Load encryptor instance
        /// </summary>
        /// <param name="encryptorConfig"></param>
        /// <returns></returns>
        internal static IEncryptor LoadEncryptor(EncryptorElement encryptorConfig)
        {
            Debug.Assert(encryptorConfig != null);

            if (!string.IsNullOrEmpty(encryptorConfig.Type)) {
                Type encryptorType = Type.GetType(encryptorConfig.Type, true);
                return (IEncryptor)Activator.CreateInstance(encryptorType);
            }
            
            // Default
            return new Encryptor();
        }
        #endregion

        #region HttpUtilities
        /// <summary>
        /// Load HTTP utilities
        /// </summary>
        /// <param name="utilitiesConfig"></param>
        /// <returns></returns>
        internal static IHttpUtilities LoadHttpUtilities(HttpUtilitiesElement utilitiesConfig)
        {
            Debug.Assert(utilitiesConfig != null);

            if (!string.IsNullOrEmpty(utilitiesConfig.Type)) {
                Type utilitiesType = Type.GetType(utilitiesConfig.Type, true);
                return (IHttpUtilities)Activator.CreateInstance(utilitiesType);
            }

            // Default
            return new HttpUtilities.HttpUtilities();
        }
        #endregion

        #region Intrusion Detector
        /// <summary>
        /// Load action instance
        /// </summary>
        /// <param name="detector">Intrusion detector instance</param>
        /// <param name="action">Action type</param>
        /// <returns></returns>
        private static bool LoadAction(IIntrusionDetector detector, Type action)
        {
            Debug.Assert(detector != null);
            Debug.Assert(action != null);

            bool loaded = false;

            object[] attrs = action.GetCustomAttributes(typeof(ActionAttribute), false);
            if (attrs != null && attrs.Length > 0) {
                ActionAttribute actionAttr = (ActionAttribute)attrs[0];

                if (actionAttr.AutoLoad) {
                    detector.AddAction(actionAttr.Name, (IAction)Activator.CreateInstance(action));
                    loaded = true;
                }
            }

            return loaded;
        }
        /// <summary>
        /// Load named action instance
        /// </summary>
        /// <param name="detector">Intrusion detector instance</param>
        /// <param name="action">Action type</param>
        /// <param name="name">Action name</param>
        private static void LoadAction(IIntrusionDetector detector, Type action, string name)
        {
            Debug.Assert(detector != null);
            Debug.Assert(action != null);
            Debug.Assert(name != null);

            detector.AddAction(name, (IAction)Activator.CreateInstance(action));
        }

        /// <summary>
        /// Load actions from assembly
        /// </summary>
        /// <param name="detector"></param>
        /// <param name="assembly"></param>
        /// <param name="typeMatch"></param>
        private static void LoadActions(IIntrusionDetector detector, Assembly assembly, Regex typeMatch)
        {
            Debug.Assert(detector != null);
            Debug.Assert(assembly != null);
            Debug.Assert(typeMatch != null);

            foreach (Type type in assembly.GetTypes()) {
                if (typeMatch.IsMatch(type.FullName)) {
                    LoadAction(detector, type);
                }
            }
        }
        /// <summary>
        /// Load instrusion detector instance
        /// </summary>
        /// <param name="detectorConfig"></param>
        /// <returns></returns>
        internal static IIntrusionDetector LoadIntrusionDetector(IntrusionDetectorElement detectorConfig)
        {
            Debug.Assert(detectorConfig != null);

            IIntrusionDetector detector = null;

            if (!string.IsNullOrEmpty(detectorConfig.Type)) {
                Type detectorType = Type.GetType(detectorConfig.Type, true);
                detector = (IIntrusionDetector)Activator.CreateInstance(detectorType);
            }
            else {
                // Create default and load all actions
                detector = new IntrusionDetector();
                LoadActions(detector, typeof(IntrusionDetector).Assembly, WildcardToRegex(@"Owasp.Esapi.IntrusionDetection.Actions.*"));
            }

            // Load actions
            foreach (AddinAssemblyElement actionAssembly in detectorConfig.Actions.Assemblies) {
                try {
                    Assembly assembly = Assembly.Load(actionAssembly.Name);
                    Regex typeMatch = WildcardToRegex( actionAssembly.Types);

                    LoadActions(detector, assembly, typeMatch);
                }
                catch (Exception exp) {
                    Esapi.Logger.Warning(LogLevels.WARN, "Failed to load action assembly", exp);
                }
            }

            // Specific actions
            foreach (ActionElement actionElement in detectorConfig.Actions) {
                string failMessage = string.Format("Failed to load action \"{0}\"", actionElement.Name);

                try {
                    Type actionType = Type.GetType(actionElement.Type, true);
                    LoadAction(detector, actionType, actionElement.Name);
                }
                catch (Exception exp) {
                    Esapi.Logger.Warning(LogLevels.WARN, failMessage, exp);
                }
            }

            // Load event thresholds
            foreach (ThresholdElement e in detectorConfig.EventThresholds) {
                string[] actions = e.Actions.Split(new char[] {','}, StringSplitOptions.RemoveEmptyEntries);

                Threshold threshold = new Threshold(e.Name, e.Count, e.Interval,actions);
                detector.AddThreshold(threshold);
            }

            return detector;
        }
        #endregion

        #region Randomizer
        /// <summary>
        /// Load randomizer instance
        /// </summary>
        /// <param name="randomizerConfig"></param>
        /// <returns></returns>
        internal static IRandomizer LoadRandomizer(RandomizerElement randomizerConfig)
        {
            Debug.Assert(randomizerConfig != null);

            if (!string.IsNullOrEmpty(randomizerConfig.Type)) {
                Type randomizerType = Type.GetType(randomizerConfig.Type, true);
                return (IRandomizer)Activator.CreateInstance(randomizerType);
            }

            // Default
            return new Randomizer();
        }
        #endregion

        #region Validator
        /// <summary>
        /// Load validation rule
        /// </summary>
        /// <param name="validator"></param>
        /// <param name="ruleType"></param>
        /// <returns></returns>
        private static bool LoadValidationRule(IValidator validator, Type ruleType)
        {
            if (ruleType == null){
                throw new ArgumentNullException("ruleType");
            }
            if (validator == null) {
                throw new ArgumentNullException("validator");
            }

            bool loaded = false;

            object[] attrs = ruleType.GetCustomAttributes(typeof(ValidationRuleAttribute), false);
            if (attrs != null && attrs.Length > 0) {
                ValidationRuleAttribute ruleAttr = (ValidationRuleAttribute)attrs[0];

                if (ruleAttr.AutoLoad) {
                    IValidationRule ruleInstance = (IValidationRule)Activator.CreateInstance(ruleType);

                    validator.AddRule(ruleAttr.Name, ruleInstance);
                    loaded = true;
                }
            }

            return loaded;
        }
        /// <summary>
        /// Load named validation rule
        /// </summary>
        /// <param name="validator"></param>
        /// <param name="ruleType"></param>
        /// <param name="name"></param>
        private static void LoadValidationRule(IValidator validator, Type ruleType, string name)
        {
            Debug.Assert(validator != null);
            Debug.Assert(ruleType != null);
            Debug.Assert(name != null);

            validator.AddRule(name, (IValidationRule)Activator.CreateInstance(ruleType));
        }
        /// <summary>
        /// Load assembly defined validation rules
        /// </summary>
        /// <param name="validator"></param>
        /// <param name="assembly"></param>
        /// <param name="typeMatch"></param>
        private static void LoadValidationRules(IValidator validator, Assembly assembly, Regex typeMatch)
        {
            Debug.Assert(validator != null);
            Debug.Assert(assembly != null);
            Debug.Assert(typeMatch != null);

            foreach (Type type in assembly.GetTypes()) {
                if (typeMatch.IsMatch(type.FullName)) {
                    LoadValidationRule(validator, type);
                }
            }
        }
        /// <summary>
        /// Load validator instance
        /// </summary>
        /// <param name="validatorConfig"></param>
        /// <returns></returns>
        internal static IValidator LoadValidator(ValidatorElement validatorConfig)
        {
            Debug.Assert(validatorConfig != null);

            IValidator validator = null;

            // Create custom
            if (!string.IsNullOrEmpty(validatorConfig.Type)) {
                Type validatorType = Type.GetType(validatorConfig.Type, true);
                validator = (IValidator)Activator.CreateInstance(validatorType);
            }
            else {
                // Create default and load local rules
                validator = new Validator();
                LoadValidationRules(validator, typeof(Validator).Assembly, WildcardToRegex(@"Owasp.Esapi.ValidationRules.*"));
            }

            ValidationRuleCollection rules = validatorConfig.Rules;
            
            // Add rule assemblies
            foreach (AddinAssemblyElement ruleAssembly in rules.Assemblies) {
                try {
                    Assembly assembly = Assembly.Load(ruleAssembly.Name);
                    Regex typeMatch = WildcardToRegex( ruleAssembly.Types);

                    LoadValidationRules(validator, assembly, typeMatch);
                }
                catch (Exception exp) {
                    Esapi.Logger.Warning(LogLevels.WARN, "Failed to load validation rule assembly", exp);
                }
            }

            // Rules
            foreach (ValidationRuleElement ruleElement in rules) {
                string failMessage = string.Format("Failed to load validation rule \"{0}\"", ruleElement.Name);

                try {
                    Type ruleType = Type.GetType(ruleElement.Type, true);
                    LoadValidationRule(validator, ruleType, ruleElement.Name);
                }
                catch (Exception exp) {
                    Esapi.Logger.Warning(LogLevels.WARN, failMessage, exp);
                }
            }

            return validator;

        }
        
        #endregion

        #region Security Configuration
        /// <summary>
        /// Load security configuration instance
        /// </summary>
        /// <param name="securityConfig"></param>
        /// <returns></returns>
        internal static ISecurityConfiguration LoadSecurityConfiguration(SecurityConfigurationElement securityConfig)
        {
            Debug.Assert(securityConfig != null);

            // Custom configuration
            if (!string.IsNullOrEmpty(securityConfig.Type)) {
                Type configType = Type.GetType(securityConfig.Type, true);
                return (ISecurityConfiguration)Activator.CreateInstance(configType);
            }

            // Default
            return new SecurityConfiguration(securityConfig);
        }
        #endregion
    }
}
