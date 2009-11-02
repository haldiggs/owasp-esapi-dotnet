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
    /// <summary>
    /// Summary description for TestContext
    /// </summary>
    [TestClass]
    public class TestContext
    {
        private MockRepository _mocks;
        private readonly string CID = Guid.NewGuid().ToString();
        private readonly string AID = Guid.NewGuid().ToString();
        private readonly string RID = Guid.NewGuid().ToString();

        [TestInitialize]
        public void Initialize()
        {
            _mocks = new MockRepository();
            EsapiRuntime.Reset();

            InitializeRuntime();
        }

        public void InitializeRuntime()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            runtime.Conditions.Register(CID, _mocks.StrictMock<ICondition>());
            runtime.Actions.Register(AID, _mocks.StrictMock<IAction>());
            runtime.Rules.Register(RID, _mocks.StrictMock<IRule>());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestContextBoundRuleFailInit()
        {
            new ContextBoundRule(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestContextBoundRulesHandlerFailProcess()
        {
            new ContextRulesHandler().ProcessEvent(null);
        }
        
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestContextBoundConditionFailInit()
        {
            new ContextBoundCondition(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestContextBoundConditionsHandlerFailProcess()
        {
            new ContextConditionsHandler().ProcessEvent(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestContextSubcontextHandlerFailProcess()
        {
            new ContextCollectionHandler().ProcessEvent(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestContextBoundActionFailInit()
        {
            new ContextBoundAction(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestContextActionsHandlerFailProcess()
        {
            new ContextActionsHandler().ProcessEvent(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestAddDuplicateContext()
        {
            string contextId = Guid.NewGuid().ToString();

            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            runtime.RegisterContext(contextId);
            runtime.RegisterContext(contextId);
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

            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            Context parent = runtime.RegisterContext(contextId);
            parent.RegisterContext(subcontextId);
            parent.RegisterContext(subcontextId);
        }

        [TestMethod]
        public void TestContextMatchTrueCondition()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            string contextId = Guid.NewGuid().ToString();
            string eventId = Guid.NewGuid().ToString();

            // Setup context
            Context context = runtime.RegisterContext(contextId);
            context.MatchConditions.Add(new ContextBoundCondition( runtime.Conditions[CID]));

            ContextBoundRule rule = new ContextBoundRule(runtime.Rules[RID]);
            rule.Events.Add(eventId);
            rule.FaultActions.Add( new ContextBoundAction(runtime.Actions[AID]));
            context.ExecuteRules.Add(rule);

            // Verify
            context = runtime.Contexts[contextId];
            Assert.IsNotNull(context);
            Assert.AreEqual(context.MatchConditions.Count, 1);
            Assert.AreEqual(context.ExecuteRules.Count, 1);

            // Set expectations
            Expect.Call( runtime.Conditions[CID].Evaluate(null))
                    .IgnoreArguments().Return(true);
            Expect.Call(delegate { runtime.Rules[RID].Process(null); })
                    .IgnoreArguments().Throw(new InvalidOperationException());
            Expect.Call(delegate { runtime.Actions[AID].Execute(null); }).IgnoreArguments();
            _mocks.ReplayAll();
            

            // Eval
            Assert.IsTrue( ((IContextHandler)context).ProcessEvent(new ContextEvent(eventId)));
            _mocks.VerifyAll();            
        }

        [TestMethod]
        public void TestContextMatchFalseCondition()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            string contextId = Guid.NewGuid().ToString();
            string eventId = Guid.NewGuid().ToString();

            // Setup context
            Context context = runtime.RegisterContext(contextId);
            context.MatchConditions.Add(new ContextBoundCondition(runtime.Conditions[CID], false));

            ContextBoundRule rule = new ContextBoundRule(runtime.Rules[RID]);
            rule.Events.Add(eventId);
            rule.FaultActions.Add(new ContextBoundAction(runtime.Actions[AID]));
            context.ExecuteRules.Add(rule);

            // Verify
            context = runtime.Contexts[contextId];
            Assert.IsNotNull(context);
            Assert.AreEqual(context.MatchConditions.Count, 1);
            Assert.AreEqual(context.ExecuteRules.Count, 1);

            // Set expectations
            Expect.Call(runtime.Conditions[CID].Evaluate(null))
                    .IgnoreArguments().Return(false);
            Expect.Call(delegate { runtime.Rules[RID].Process(null); })
                    .IgnoreArguments().Throw(new InvalidOperationException());
            Expect.Call(delegate { runtime.Actions[AID].Execute(null); }).IgnoreArguments();
            _mocks.ReplayAll();


            // Eval
            Assert.IsTrue(((IContextHandler)context).ProcessEvent(new ContextEvent(eventId)));
            _mocks.VerifyAll();
        }

        [TestMethod]
        public void TestContextFailCondition()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            string contextId = Guid.NewGuid().ToString();
            string eventId = Guid.NewGuid().ToString();

            // Setup context
            Context context = runtime.RegisterContext(contextId);
            context.MatchConditions.Add(new ContextBoundCondition(runtime.Conditions[CID]));

            ContextBoundRule rule = new ContextBoundRule(runtime.Rules[RID]);
            rule.Events.Add(eventId);
            rule.FaultActions.Add(new ContextBoundAction(runtime.Actions[AID]));
            context.ExecuteRules.Add(rule);

            // Verify
            context = runtime.Contexts[contextId];
            Assert.IsNotNull(context);
            Assert.AreEqual(context.MatchConditions.Count, 1);
            Assert.AreEqual(context.ExecuteRules.Count, 1);

            // Set expectations
            Expect.Call(runtime.Conditions[CID].Evaluate(null))
                    .IgnoreArguments().Return(false);
            _mocks.ReplayAll();
            
            // Eval
            Assert.IsFalse(((IContextHandler)context).ProcessEvent(new ContextEvent(eventId)));
            _mocks.VerifyAll();
        }

        [TestMethod]
        public void TestContextRuleNoFault()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            string contextId = Guid.NewGuid().ToString();
            string eventId = Guid.NewGuid().ToString();

            // Setup context
            Context context = runtime.RegisterContext(contextId);
            context.MatchConditions.Add(new ContextBoundCondition(runtime.Conditions[CID]));

            ContextBoundRule rule = new ContextBoundRule(runtime.Rules[RID]);
            rule.Events.Add(eventId);
            rule.FaultActions.Add(new ContextBoundAction(runtime.Actions[AID]));
            context.ExecuteRules.Add(rule);

            // Verify
            context = runtime.Contexts[contextId];
            Assert.IsNotNull(context);
            Assert.AreEqual(context.MatchConditions.Count, 1);
            Assert.AreEqual(context.ExecuteRules.Count, 1);

            // Set expectations
            Expect.Call(runtime.Conditions[CID].Evaluate(null))
                    .IgnoreArguments().Return(true);
            Expect.Call(delegate { runtime.Rules[RID].Process(null); })
                    .IgnoreArguments();
            _mocks.ReplayAll();


            // Eval
            Assert.IsTrue(((IContextHandler)context).ProcessEvent(new ContextEvent(eventId)));
            _mocks.VerifyAll();
        }

        [TestMethod]
        public void TestContextRuleFault()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            string contextId = Guid.NewGuid().ToString();
            string eventId = Guid.NewGuid().ToString();

            // Setup context
            Context context = runtime.RegisterContext(contextId);
            context.MatchConditions.Add(new ContextBoundCondition(runtime.Conditions[CID]));

            ContextBoundRule rule = new ContextBoundRule(runtime.Rules[RID]);
            rule.Events.Add(eventId);
            rule.FaultActions.Add(new ContextBoundAction(runtime.Actions[AID]));
            context.ExecuteRules.Add(rule);

            // Verify
            context = runtime.Contexts[contextId];
            Assert.IsNotNull(context);
            Assert.AreEqual(context.MatchConditions.Count, 1);
            Assert.AreEqual(context.ExecuteRules.Count, 1);

            // Set expectations
            Expect.Call(runtime.Conditions[CID].Evaluate(null))
                    .IgnoreArguments().Return(true);
            Expect.Call(delegate { runtime.Rules[RID].Process(null); })
                    .IgnoreArguments().Throw(new InvalidOperationException());
            Expect.Call(delegate { runtime.Actions[AID].Execute(null); }).IgnoreArguments();
            _mocks.ReplayAll();


            // Eval
            Assert.IsTrue(((IContextHandler)context).ProcessEvent(new ContextEvent(eventId)));
            _mocks.VerifyAll();
        }

        [TestMethod]
        public void TestContextRuleFaultActionFault()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            string contextId = Guid.NewGuid().ToString();
            string eventId = Guid.NewGuid().ToString();

            // Setup context
            Context context = runtime.RegisterContext(contextId);
            context.MatchConditions.Add(new ContextBoundCondition(runtime.Conditions[CID]));

            // This rule should be skipped - event does not match
            ContextBoundRule ruleNoMatch = new ContextBoundRule(runtime.Rules[RID]);
            ruleNoMatch.Events.Add(Guid.NewGuid().ToString());
            ruleNoMatch.FaultActions.Add(new ContextBoundAction(runtime.Actions[AID]));
            context.ExecuteRules.Add(ruleNoMatch);

            // This rule should run - event will match
            ContextBoundRule ruleMatch = new ContextBoundRule(runtime.Rules[RID]);
            ruleMatch.Events.Add(eventId);
            ruleMatch.FaultActions.Add(new ContextBoundAction(runtime.Actions[AID]));
            context.ExecuteRules.Add(ruleMatch);

            // Verify
            context = runtime.Contexts[contextId];
            Assert.IsNotNull(context);
            Assert.AreEqual(context.MatchConditions.Count, 1);
            Assert.AreEqual(context.ExecuteRules.Count, 2);

            // Set expectations
            Expect.Call(runtime.Conditions[CID].Evaluate(null))
                    .IgnoreArguments().Return(true)
                    .Repeat.Times(1);
            Expect.Call(() => runtime.Rules[RID].Process(null))
                    .IgnoreArguments().Throw(new InvalidOperationException())
                    .Repeat.Times(1);
            Expect.Call(() => runtime.Actions[AID].Execute(null))
                    .IgnoreArguments().Throw(new Exception("ActionFault"))
                    .Repeat.Times(1);
            _mocks.ReplayAll();

            try {
                Assert.IsTrue(((IContextHandler)context).ProcessEvent(new ContextEvent(eventId)));
                Assert.Fail("Action exception not thrown");
            }
            catch (Exception exp) {
                Assert.AreEqual(exp.Message, "ActionFault");
            }
            _mocks.VerifyAll();
        }

        [TestMethod]
        public void TestAddSubcontext()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            string contextId = Guid.NewGuid().ToString();
            string subcontextId = Guid.NewGuid().ToString();

            // Add context
            Context context = runtime.RegisterContext(contextId);
            Assert.IsNotNull(runtime.Contexts[contextId]);
            Assert.AreEqual(runtime.Contexts.Count, 1);

            // Add subcontext
            Context subcontext = context.RegisterContext(subcontextId);
            Assert.AreEqual(context.SubContexts.Count, 1);
            Assert.IsTrue(context.SubContexts.Contains(subcontext));
        }

        [TestMethod]
        public void TestMatchContextMatchSubcontext()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            string contextId = Guid.NewGuid().ToString();
            string subcontextId = Guid.NewGuid().ToString();
            string eventId = Guid.NewGuid().ToString();

            ContextBoundCondition boundCondition = new ContextBoundCondition(runtime.Conditions[CID], true);
            ContextBoundRule boundRule = new ContextBoundRule(runtime.Rules[RID]);
            boundRule.Events.Add(eventId);

            // Add context
            Context context = runtime.RegisterContext(contextId);
            Assert.IsNotNull(runtime.Contexts[contextId]);
            Assert.AreEqual(runtime.Contexts.Count, 1);
            context.MatchConditions.Add(boundCondition);

            // Add subcontext
            Context subcontext = context.RegisterContext(subcontextId);
            Assert.AreEqual(context.SubContexts.Count, 1);
            Assert.IsTrue(context.SubContexts.Contains(subcontext));
            subcontext.MatchConditions.Add(boundCondition);
            subcontext.ExecuteRules.Add(boundRule);

            // Set expectations
            Expect.Call(boundCondition.Condition.Evaluate(null))
                .IgnoreArguments().Return(true)
                .Repeat.Any(); // condition eval may be cached
            Expect.Call( () => boundRule.Rule.Process(null))
                .IgnoreArguments()
                .Repeat.Times(1);
            _mocks.ReplayAll();

            Assert.IsTrue(((IContextHandler)context).ProcessEvent(new ContextEvent(eventId)));
            _mocks.VerifyAll();
        }
    }
}
