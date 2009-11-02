using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Rhino.Mocks;
using Owasp.Esapi.Interfaces;
using Owasp.Esapi;
using Owasp.Esapi.Runtime;

namespace EsapiTest.Runtime
{
    /// <summary>
    /// Summary description for TestRuntimeConditions
    /// </summary>
    [TestClass]
    public class TestRuntimeConditions
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
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);
        }

        [TestMethod]
        public void TestFluentAddConditions()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            // Create and add conditions
            IDictionary<string, ICondition> conditions = ObjectRepositoryMock.MockNamedObjects<ICondition>(_mocks, 10);

            ObjectRepositoryMock.AddNamedObjects<ICondition>(conditions, runtime.Conditions);
            ObjectRepositoryMock.AssertContains<ICondition>(conditions, runtime.Conditions);

            // Call conditions
            ObjectRepositoryMock.ForEach<ICondition>(runtime.Conditions,
                new Action<ICondition>(
                    delegate(ICondition condition)
                    {
                        Expect.Call(condition.Evaluate(ConditionArgs.Empty)).Return(false);
                    }));
            _mocks.ReplayAll();

            ObjectRepositoryMock.ForEach<ICondition>(runtime.Conditions,
                new Action<ICondition>(
                    delegate(ICondition condition)
                    {
                        Assert.IsFalse(condition.Evaluate(ConditionArgs.Empty));
                    }));
            _mocks.VerifyAll();    
        }

        [TestMethod]
        public void TestFluentAddInvalidConditionParams()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            try {
                runtime.Conditions.Register(null, _mocks.StrictMock<ICondition>());
                Assert.Fail("Null condition name");
            }
            catch (ArgumentException) {
            }

            try {
                runtime.Conditions.Register(string.Empty, _mocks.StrictMock<ICondition>());
                Assert.Fail("Empty condition name");
            }
            catch (ArgumentException) {
            }

            try {
                runtime.Conditions.Register(Guid.NewGuid().ToString(), null);
                Assert.Fail("Null condition");
            }
            catch (ArgumentNullException) {
            }
        }

        [TestMethod]
        public void TestRemoveCondition()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            ObjectRepositoryMock.AssertMockAddRemove<ICondition>(_mocks, runtime.Conditions);
        }
    }
}
