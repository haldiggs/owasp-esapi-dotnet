using System;
using NUnit.Framework;
using Owasp.Esapi.Runtime;
using Rhino.Mocks;

namespace EsapiTest.Runtime
{
    /// <summary>
    /// Summary description for TestRuntimeRules
    /// </summary>
    [TestFixture]
    public class TestRuntimeRules
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
        public void TestFluentAddInvalidRuleParams()
        {
            Assert.IsNotNull(_runtime);

            try {
                _runtime.Rules.Register(null, _mocks.StrictMock<IRule>());
                Assert.Fail("Null rule name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.Rules.Register(string.Empty, _mocks.StrictMock<IRule>());
                Assert.Fail("Empty rule name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.Rules.Register(Guid.NewGuid().ToString(), null);
                Assert.Fail("Null rule");
            }
            catch (ArgumentNullException) {
            }
        }

        [Test]
        public void TestRemoveRule()
        {
            Assert.IsNotNull(_runtime);

            ObjectRepositoryMock.AssertMockAddRemove<IRule>(_mocks, _runtime.Rules);
        }
    }
}
