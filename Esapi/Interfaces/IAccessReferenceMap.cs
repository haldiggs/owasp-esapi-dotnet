using System;
using System.Collections;

namespace Owasp.Esapi.Interfaces
{
    interface IAccessReferenceMap
    {
        String GetIndirectReference(Object directReference);

        Object GetDirectReference(String indirectReference);

        ICollection GetIndirectReferences();

        ICollection GetDirectReferences();

        String AddDirectReference(Object direct);

        String RemoveDirectReference(Object direct);

        void Update(IEnumerable directReferences);
    }
}
