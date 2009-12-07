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
        private EsapiRuntime _runtime;

        [TestInitialize]
        public void Initialize()
        {
            _mocks = new MockRepository();
            _runtime = new EsapiRuntime();
        }

                
        [TestMethod]
        public void TestGetRuntime()
        {
            Assert.IsNotNull(_runtime);
        }

        [TestMethod]
        public void TestFluentAddActions()
        {            
            Assert.IsNotNull(_runtime);

            // Create and add actions
            IDictionary<string, IAction> actions = ObjectRepositoryMock.MockNamedObjects<IAction>(_mocks, 10);

            ObjectRepositoryMock.AddNamedObjects<IAction>(actions, _runtime.Actions);
            ObjectRepositoryMock.AssertContains<IAction>(actions, _runtime.Actions);

            // Call actions
            ObjectRepositoryMock.ForEach<IAction>(_runtime.Actions,
                new Action<IAction>( 
                    delegate(IAction action) {
                        Expect.Call(delegate { action.Execute(ActionArgs.Empty); });
                    }));
            _mocks.ReplayAll();

            ObjectRepositoryMock.ForEach<IAction>(_runtime.Actions,
                new Action<IAction>(
                    delegate(IAction action) {
                        action.Execute(ActionArgs.Empty);
                    }));
            _mocks.VerifyAll();            
        }

        [TestMethod]        
        public void TestFluentAddInvalidActionParams()
        {
            Assert.IsNotNull(_runtime);

            try {
                _runtime.Actions.Register(null, _mocks.StrictMock<IAction>());
                Assert.Fail("Null action name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.Actions.Register(string.Empty, _mocks.StrictMock<IAction>());
                Assert.Fail("Empty action name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.Actions.Register(Guid.NewGuid().ToString(), null);
                Assert.Fail("Null action");
            }
            catch (ArgumentNullException) {
            }
        }

        [TestMethod]
        public void TestRemoveAction()
        {
            Assert.IsNotNull(_runtime);

            ObjectRepositoryMock.AssertMockAddRemove<IAction>(_mocks, _runtime.Actions);
        }
    }
}
