using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Rhino.Mocks;
using Owasp.Esapi.Runtime;
using Owasp.Esapi.Interfaces;

namespace EsapiTest.Runtime
{
    delegate void RuntimeSubscribe(IRuntimeEventPublisher pub);

    internal class RuntimeEventSource : IRuntimeEventPublisher
    {
        #region IRuntimeEventPublisher Members
        public event EventHandler<RuntimeEventArgs> PreRequestHandlerExecute;
        public event EventHandler<RuntimeEventArgs> PostRequestHandlerExecute;
        #endregion

        public void FirePreRequestHandlerExecute()
        {
            if (PreRequestHandlerExecute != null) {
                PreRequestHandlerExecute(this, new RuntimeEventArgs());
            }
        }
        public void FirePostRequestHandlerExecute()
        {
            if (PostRequestHandlerExecute != null) {
                PostRequestHandlerExecute(this, new RuntimeEventArgs());
            }
        }
    }

    /// <summary>
    /// Summary description for TestContext
    /// </summary>
    [TestClass]
    public class TestContext
    {
        private MockRepository _mocks;
        private EsapiRuntime _runtime;

        private readonly string CID = Guid.NewGuid().ToString();
        private readonly string AID = Guid.NewGuid().ToString();
        private readonly string RID = Guid.NewGuid().ToString();

        [TestInitialize]
        public void Initialize()
        {
            _mocks = new MockRepository();
            _runtime = new EsapiRuntime();
            
            InitializeRuntime();
        }

        [TestCleanup]
        public void TearDown()
        {
        }

        public void InitializeRuntime()
        {
            Assert.IsNotNull(_runtime);

            _runtime.Conditions.Register(CID, _mocks.StrictMock<ICondition>());
            _runtime.Actions.Register(AID, _mocks.StrictMock<IAction>());
            _runtime.Rules.Register(RID, _mocks.StrictMock<IRule>());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestAddDuplicateContext()
        {
            string contextId = Guid.NewGuid().ToString();

            Assert.IsNotNull(_runtime);

            _runtime.CreateContext(contextId);
            _runtime.CreateContext(contextId);
        }

        [TestMethod]
        public void TestContextFailInit()
        {
            try {
                new Context(null);
                Assert.Fail("Null id");
            }
            catch (ArgumentException) {
            }

            try {
                new Context(string.Empty);
                Assert.Fail("Empty id");
            }
            catch (ArgumentException) {
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestAddDuplicateSubContext()
        {
            string contextId = Guid.NewGuid().ToString();
            string subcontextId = Guid.NewGuid().ToString();

            Assert.IsNotNull(_runtime);

            IContext parent = _runtime.CreateContext(contextId);
            parent.CreateSubContext(subcontextId);
            parent.CreateSubContext(subcontextId);
        }

        [TestMethod]
        public void TestContextMatchTrueCondition()
        {
            Assert.IsNotNull(_runtime);

            string contextId = Guid.NewGuid().ToString();
            string eventId = Guid.NewGuid().ToString();

            // Setup conditions
            IContext context = _runtime.CreateContext(contextId);
            context.BindCondition(_runtime.Conditions.Get(CID), true);
            Assert.AreEqual(context.MatchConditions.Count, 1);

            // Setup rule
            IRule rule = _runtime.Rules.Get(RID);
            Expect.Call(delegate { rule.Subscribe(null); }).IgnoreArguments()
                .Do((RuntimeSubscribe)
                // Register to throw exceptions for each published event
                delegate(IRuntimeEventPublisher pub) {
                    pub.PreRequestHandlerExecute += delegate(object sender, RuntimeEventArgs args) {
                        throw new InvalidOperationException();
                    };
                    pub.PostRequestHandlerExecute += delegate(object sender, RuntimeEventArgs args) {
                        throw new AccessViolationException();
                    };
                });
                   
            // Set expectations for prerequest
            Expect.Call( _runtime.Conditions.Get(CID).Evaluate(null))
                .IgnoreArguments().Return(true);
            Expect.Call(delegate { _runtime.Actions.Get(AID).Execute(null); }).IgnoreArguments();
            // Set expectations for postrequest
            Expect.Call(_runtime.Conditions.Get(CID).Evaluate(null))
                .IgnoreArguments().Return(true);
            Expect.Call(delegate { _runtime.Actions.Get(AID).Execute(null); }).IgnoreArguments();
            _mocks.ReplayAll();


            // Verify            
            context.BindRule(rule).FaultActions.Add(_runtime.Actions.Get(AID));
            Assert.AreEqual(context.ExecuteRules.Count, 1);
            
            // Verify event handlers
            RuntimeEventSource source = new RuntimeEventSource();
            _runtime.Subscribe(source);
            source.FirePreRequestHandlerExecute();
            source.FirePostRequestHandlerExecute();

            _mocks.VerifyAll();            
        }
    }
}
