using System;
using System.Collections.Generic;
using NUnit.Framework;
using Owasp.Esapi.Runtime;
using Rhino.Mocks;

namespace EsapiTest.Runtime
{
    /// <summary>
    /// Summary description for TestRuntimeConditions
    /// </summary>
    [TestFixture]
    public class TestRuntimeConditions
    {
        private MockRepository _mocks;
        private EsapiRuntime _runtime;

        [SetUp]
        public void Initialize()
        {
            _mocks = new MockRepository();
            _runtime = new EsapiRuntime();
        }


        [Test]
        public void TestGetRuntime()
        {
            Assert.IsNotNull(_runtime);
        }

        [Test]
        public void TestFluentAddConditions()
        {
            Assert.IsNotNull(_runtime);

            // Create and add conditions
            IDictionary<string, ICondition> conditions = ObjectRepositoryMock.MockNamedObjects<ICondition>(_mocks, 10);

            ObjectRepositoryMock.AddNamedObjects<ICondition>(conditions, _runtime.Conditions);
            ObjectRepositoryMock.AssertContains<ICondition>(conditions, _runtime.Conditions);

            // Call conditions
            ObjectRepositoryMock.ForEach<ICondition>(_runtime.Conditions,
                new Action<ICondition>(
                    delegate(ICondition condition)
                    {
                        Expect.Call(condition.Evaluate(ConditionArgs.Emtpy)).Return(false);
                    }));
            _mocks.ReplayAll();

            ObjectRepositoryMock.ForEach<ICondition>(_runtime.Conditions,
                new Action<ICondition>(
                    delegate(ICondition condition)
                    {
                        Assert.IsFalse(condition.Evaluate(ConditionArgs.Emtpy));
                    }));
            _mocks.VerifyAll();    
        }

        [Test]
        public void TestFluentAddInvalidConditionParams()
        {
            Assert.IsNotNull(_runtime);

            try {
                _runtime.Conditions.Register(null, _mocks.StrictMock<ICondition>());
                Assert.Fail("Null condition name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.Conditions.Register(string.Empty, _mocks.StrictMock<ICondition>());
                Assert.Fail("Empty condition name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.Conditions.Register(Guid.NewGuid().ToString(), null);
                Assert.Fail("Null condition");
            }
            catch (ArgumentNullException) {
            }
        }

        [Test]
        public void TestRemoveCondition()
        {
            Assert.IsNotNull(_runtime);

            ObjectRepositoryMock.AssertMockAddRemove<ICondition>(_mocks, _runtime.Conditions);
        }
    }
}
