using System;
using System.Collections.Generic;
using NUnit.Framework;
using Owasp.Esapi.Runtime;
using Rhino.Mocks;

namespace EsapiTest.Runtime
{
    /// <summary>
    /// Summary description for TestRuntimeContexts
    /// </summary>
    [TestFixture]
    public class TestRuntimeContexts
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
        public void TestAddContexts()
        {
            Assert.IsNotNull(_runtime);

            // Create and add contexts
            IDictionary<string, IContext> contexts = ObjectRepositoryMock.MockNamedObjects<IContext>(_mocks, 10);

            // Add 
            foreach (string key in contexts.Keys) {
                _runtime.RegisterContext(key, contexts[key]);
            }

            // Verify
            Assert.AreEqual(contexts.Count, _runtime.Contexts.Count);

            foreach (string k in contexts.Keys) {
                Assert.AreEqual(contexts[k], _runtime.LookupContext(k));
            }
        }

        [Test]
        public void TestAddInvalidContextParams()
        {
            Assert.IsNotNull(_runtime);

            try {
                _runtime.RegisterContext(null,_mocks.StrictMock<IContext>());
                Assert.Fail("Null context name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.RegisterContext(string.Empty, _mocks.StrictMock<IContext>());
                Assert.Fail("Empty context name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.RegisterContext(Guid.NewGuid().ToString(), null);
                Assert.Fail("Null context");
            }
            catch (ArgumentNullException) {
            }
        }

        [Test]
        public void TestContextAddInvalidParams()
        {
            Assert.IsNotNull(_runtime);

            try {
                _runtime.CreateContext(null);
                Assert.Fail("Null context name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.CreateContext(string.Empty);
                Assert.Fail("Empty context name");
            }
            catch (ArgumentException) {
            }
        }

        [Test]
        public void TestRemoveContext()
        {
            Assert.IsNotNull(_runtime);

            IContext ctx = _runtime.CreateContext();
            Assert.IsNotNull(ctx);
            Assert.AreEqual(1, _runtime.Contexts.Count);
            Assert.AreEqual(ctx, _runtime.LookupContext(ctx.Name));

            Assert.AreEqual(_runtime.RemoveContext(ctx.Name), ctx);
            Assert.AreEqual(0, _runtime.Contexts.Count);
        }
    }
}
