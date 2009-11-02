using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi.Interfaces;
using Rhino.Mocks;
using Owasp.Esapi;
using Owasp.Esapi.Runtime;

namespace EsapiTest.Runtime
{
    /// <summary>
    /// Summary description for TestRuntimeContexts
    /// </summary>
    [TestClass]
    public class TestRuntimeContexts
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
        public void TestFluentAddContexts()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            // Create and add contexts
            IDictionary<string, Context> contexts = ObjectRepositoryMock.MockNamedObjects<Context>(
                            () => _mocks.CreateMock<Context>(Guid.NewGuid().ToString()), 
                            10);

            ObjectRepositoryMock.AddNamedObjects<Context>(contexts, runtime.Contexts);
            ObjectRepositoryMock.AssertContains<Context>(contexts, runtime.Contexts);
        }

        [TestMethod]
        public void TestFluentAddInvalidContextParams()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            try {
                runtime.Contexts.Register(null,_mocks.StrictMock<Context>(Guid.NewGuid().ToString()));
                Assert.Fail("Null context name");
            }
            catch (ArgumentException) {
            }

            try {
                runtime.Contexts.Register(string.Empty, _mocks.StrictMock<Context>(Guid.NewGuid().ToString()));
                Assert.Fail("Empty context name");
            }
            catch (ArgumentException) {
            }

            try {
                runtime.Contexts.Register(Guid.NewGuid().ToString(), null);
                Assert.Fail("Null context");
            }
            catch (ArgumentNullException) {
            }
        }

        [TestMethod]
        public void TestContextAddInvalidParams()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            try {
                runtime.RegisterContext(null);
                Assert.Fail("Null context name");
            }
            catch (ArgumentException) {
            }

            try {
                runtime.RegisterContext(string.Empty);
                Assert.Fail("Empty context name");
            }
            catch (ArgumentException) {
            }
        }

        [TestMethod]
        public void TestRemoveContext()
        {
            EsapiRuntime runtime = EsapiRuntime.Current;
            Assert.IsNotNull(runtime);

            ObjectRepositoryMock.AssertMockAddRemove<Context>(
                () => _mocks.CreateMock<Context>(Guid.NewGuid().ToString()), 
                runtime.Contexts);
        }
    }
}
