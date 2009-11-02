using System;
using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;
using Owasp.Esapi.Configuration;
using Owasp.Esapi.Interfaces;

namespace Owasp.Esapi.IntrusionDetection
{
    internal class IntrusionDetectorLoader
    {
        /// <summary>
        /// Load action instance
        /// </summary>
        /// <param name="detector">Intrusion detector instance</param>
        /// <param name="action">Action type</param>
        /// <returns></returns>
        private static bool LoadAction(IntrusionDetector detector, Type action)
        {
            Debug.Assert(detector != null);
            Debug.Assert(action != null);

            bool loaded = false;

            object[] attrs = action.GetCustomAttributes(typeof(ActionAttribute), false);
            if (attrs != null && attrs.Length > 0) {
                ActionAttribute actionAttr = (ActionAttribute)attrs[0];

                if (actionAttr.AutoLoad) {
                    detector.AddAction(actionAttr.Name, ObjectBuilder.Build<IAction>(action));
                    loaded = true;
                }
            }

            return loaded;
        }

        /// <summary>
        /// Load actions from assembly
        /// </summary>
        /// <param name="detector"></param>
        /// <param name="assembly"></param>
        /// <param name="typeMatch"></param>
        private static void LoadActions(IntrusionDetector detector, Assembly assembly, Regex typeMatch)
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
        internal static IIntrusionDetector Load(IntrusionDetectorElement detectorConfig)
        {
            Debug.Assert(detectorConfig != null);

            if (!string.IsNullOrEmpty(detectorConfig.Type)) {
                return ObjectBuilder.Build<IIntrusionDetector>(detectorConfig.Type);
            }

            // Create default and load all actions
            IntrusionDetector detector = new IntrusionDetector();
            LoadActions(detector, typeof(IntrusionDetector).Assembly, MatchHelper.WildcardToRegex(@"Owasp.Esapi.IntrusionDetection.Actions.*"));
            
            // Load actions
            foreach (AddinAssemblyElement actionAssembly in detectorConfig.Actions.Assemblies) {
                try {
                    Assembly assembly = Assembly.Load(actionAssembly.Name);
                    Regex typeMatch = MatchHelper.WildcardToRegex(actionAssembly.Types);

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
                    detector.AddAction(actionElement.Name, AddinBuilder<IAction>.MakeInstance(actionElement));
                }
                catch (Exception exp) {
                    Esapi.Logger.Warning(LogLevels.WARN, failMessage, exp);
                }
            }

            // Load event thresholds
            foreach (ThresholdElement e in detectorConfig.EventThresholds) {
                string[] actions = e.Actions.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                Threshold threshold = new Threshold(e.Name, e.Count, e.Interval, actions);
                detector.AddThreshold(threshold);
            }

            return detector;
        }
    }
}
