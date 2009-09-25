using Owasp.Esapi.Interfaces;

namespace EsapiTest.Surrogates
{
    //Forward intrusion detector
    internal class SurrogateIntrusionDetector : IIntrusionDetector
    {
        internal static IIntrusionDetector DefaultDetector;
        private IIntrusionDetector _detector;

        public IIntrusionDetector Impl
        {
            get { return _detector == null ? DefaultDetector : _detector; }
            set { _detector = value; }
        }

        #region IIntrusionDetector Members

        public void AddAction(string name, IAction action)
        {
            Impl.AddAction(name, action);
        }

        public bool RemoveAction(string name)
        {
            return Impl.RemoveAction(name);
        }

        public IAction GetAction(string name)
        {
            return Impl.GetAction(name);
        }

        public void AddThreshold(Owasp.Esapi.Threshold threshold)
        {
            Impl.AddThreshold(threshold);
        }

        public bool RemoveThreshold(string eventName)
        {
            return Impl.RemoveThreshold(eventName);
        }

        public void AddException(System.Exception exception)
        {
            Impl.AddException(exception);
        }

        public void AddEvent(string eventName)
        {
            Impl.AddEvent(eventName);
        }

        #endregion
    }

    // Forward action
    internal class SurrogateAction : IAction
    {
        public IAction Impl { get; set; }

        #region IAction Members

        public void Execute(Owasp.Esapi.ActionArgs args)
        {
            Impl.Execute(args);
        }

        #endregion
    }

}
