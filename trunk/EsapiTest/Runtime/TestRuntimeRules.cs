using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Interfaces;
using Rhino.Mocks;
using Owasp.Esapi.Runtime;

namespace EsapiTest.Runtime
{
    /// <summary>
    /// Summary description for TestRuntimeRules
    /// </summary>
    [TestClass]
    public class TestRuntimeRules
    {
        private MockRepository _mocks;

        [TestInitialize]
        public void Initialize()
        {
            _mocks = new MockRepository();
            EsapiRuntime.Reset();
        }


        [TestMethod]
        public void TestGetRuntime()
        {
            Assert.IsNotNull(EsapiRuntime.Current);
        }

        [TestMethod]
        public void TestFluentAddRules()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            // Create and add rules
            IDictionary<string, IRule> rules = ObjectRepositoryMock.MockNamedObjects<IRule>(_mocks, 10);

            ObjectRepositoryMock.AddNamedObjects<IRule>(rules, runtime.Rules);
            ObjectRepositoryMock.AssertContains<IRule>(rules, runtime.Rules);

            // Call rules
            ObjectRepositoryMock.ForEach<IRule>(runtime.Rules,
                new Action<IRule>(
                    delegate(IRule rule)
                    {
                        Expect.Call( delegate { rule.Process(RuleArgs.Empty); });
                    }));
            _mocks.ReplayAll();

            ObjectRepositoryMock.ForEach<IRule>(runtime.Rules,
                new Action<IRule>(
                    delegate(IRule rule)
                    {
                        rule.Process(RuleArgs.Empty);
                    }));
            _mocks.VerifyAll();
        }

        [TestMethod]
        public void TestFluentAddInvalidRuleParams()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            try {
                runtime.Rules.Register(null, _mocks.StrictMock<IRule>());
                Assert.Fail("Null rule name");
            }
            catch (ArgumentException) {
            }

            try {
                runtime.Rules.Register(string.Empty, _mocks.StrictMock<IRule>());
                Assert.Fail("Empty rule name");
            }
            catch (ArgumentException) {
            }

            try {
                runtime.Rules.Register(Guid.NewGuid().ToString(), null);
                Assert.Fail("Null rule");
            }
            catch (ArgumentNullException) {
            }
        }

        [TestMethod]
        public void TestRemoveRule()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            ObjectRepositoryMock.AssertMockAddRemove<IRule>(_mocks, runtime.Rules);
        }
    }
}
