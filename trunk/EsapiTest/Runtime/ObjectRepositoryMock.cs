using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi.Runtime;
using Rhino.Mocks;

namespace EsapiTest.Runtime
{
    internal class ObjectRepositoryMock
    {
        /// <summary>
        /// Create named objects dictionary
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="mocks"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        internal static IDictionary<string, T> MockNamedObjects<T>(MockRepository mocks, int size)
            where T : class
        {
            Assert.IsNotNull(mocks);
            return MockNamedObjects<T>(() => mocks.StrictMock<T>(), size);
        }
        /// <summary>
        /// Create named objects dictionary
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="size"></param>
        /// <returns></returns>
        internal static IDictionary<string, T> MockNamedObjects<T>(Func<T> mockFactory, int size)
            where T : class
        {
            Assert.IsNotNull(mockFactory);
            Assert.IsTrue(size > 0);

            Dictionary<string, T> objects = new Dictionary<string, T>();

            for (int i = 0; i < size; ++i) {
                objects[Guid.NewGuid().ToString()] = mockFactory();
            }

            return objects;
        }
        /// <summary>
        /// Add named objects
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="from"></param>
        /// <param name="to"></param>
        internal static void AddNamedObjects<T>(IDictionary<string, T> from, IObjectRepository<string, T> to)
            where T : class
        {
            foreach (string k in from.Keys) {
                to.Register(k, from[k]);
            }
        }
        /// <summary>
        /// Assert contains
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="source"></param>
        /// <param name="target"></param>
        internal static void AssertContains<T>(IDictionary<string, T> source, IObjectRepository<string, T> target)
            where T : class
        {
            Assert.AreEqual(source.Count, target.Count);

            foreach (string k in source.Keys) {
                Assert.AreEqual(source[k], target.Get(k));
            }
        }
        /// <summary>
        /// For each
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="objects"></param>
        /// <param name="action"></param>
        internal static void ForEach<T>(IObjectRepository<string, T> objects, Action<T> action)
            where T : class
        {
            foreach (T v in objects.Objects) {
                action(v);
            }
        }
        /// <summary>
        /// Assert create remove
        /// </summary>
        /// <param name="objects"></param>
        internal static void AssertMockAddRemove<T>(Func<T> mockFactory, IObjectRepository<string, T> objects)
            where T : class
        {
            Assert.IsNotNull(mockFactory);
            Assert.IsNotNull(objects);

            string name = Guid.NewGuid().ToString();
            T t = mockFactory();

            objects.Register(name, t);
            Assert.AreEqual(objects.Get(name), t);

            objects.Revoke(name);
            Assert.IsFalse(objects.Objects.Contains(t));
            Assert.IsFalse(objects.Ids.Contains(name));
        }

        internal static void AssertMockAddRemove<T>(MockRepository mocks, IObjectRepository<string, T> objects)
          where T : class
        {
            Assert.IsNotNull(mocks);
            AssertMockAddRemove<T>(() => mocks.StrictMock<T>(), objects);
        }
    }
}
