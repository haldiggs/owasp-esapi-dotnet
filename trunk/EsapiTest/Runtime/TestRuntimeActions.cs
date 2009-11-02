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
    /// Summary description for TestRuntime
    /// </summary>
    [TestClass]
    public class TestRuntimeActions
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
        public void TestFluentAddActions()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            // Create and add actions
            IDictionary<string, IAction> actions = ObjectRepositoryMock.MockNamedObjects<IAction>(_mocks, 10);

            ObjectRepositoryMock.AddNamedObjects<IAction>(actions, runtime.Actions);
            ObjectRepositoryMock.AssertContains<IAction>(actions, runtime.Actions);

            // Call actions
            ObjectRepositoryMock.ForEach<IAction>(runtime.Actions,
                new Action<IAction>( 
                    delegate(IAction action) {
                        Expect.Call(delegate { action.Execute(ActionArgs.Empty); });
                    }));
            _mocks.ReplayAll();

            ObjectRepositoryMock.ForEach<IAction>(runtime.Actions,
                new Action<IAction>(
                    delegate(IAction action) {
                        action.Execute(ActionArgs.Empty);
                    }));
            _mocks.VerifyAll();            
        }

        [TestMethod]        
        public void TestFluentAddInvalidActionParams()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            try {
                runtime.Actions.Register(null, _mocks.StrictMock<IAction>());
                Assert.Fail("Null action name");
            }
            catch (ArgumentException) {
            }

            try {
                runtime.Actions.Register(string.Empty, _mocks.StrictMock<IAction>());
                Assert.Fail("Empty action name");
            }
            catch (ArgumentException) {
            }

            try {
                runtime.Actions.Register(Guid.NewGuid().ToString(), null);
                Assert.Fail("Null action");
            }
            catch (ArgumentNullException) {
            }
        }

        [TestMethod]
        public void TestRemoveAction()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            ObjectRepositoryMock.AssertMockAddRemove<IAction>(_mocks, runtime.Actions);
        }
    }
}
