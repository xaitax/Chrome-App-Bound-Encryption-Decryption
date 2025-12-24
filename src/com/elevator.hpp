// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include <wrl/client.h>
#include <string>
#include <vector>

namespace Com {

    enum class ProtectionLevel {
        None = 0,
        PathValidationOld = 1,
        PathValidation = 2,
        Max = 3
    };

    // Interface definitions
    MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
    IOriginalBaseElevator : public IUnknown {
    public:
        virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
        virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
        virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
    };

    MIDL_INTERFACE("E12B779C-CDB8-4F19-95A0-9CA19B31A8F6")
    IEdgeElevatorBase_Placeholder : public IUnknown {
    public:
        virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod1_Unknown(void) = 0;
        virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod2_Unknown(void) = 0;
        virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod3_Unknown(void) = 0;
    };

    MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
    IEdgeIntermediateElevator : public IEdgeElevatorBase_Placeholder {
    public:
        virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
        virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
        virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
    };

    MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
    IEdgeElevatorFinal : public IEdgeIntermediateElevator{};

    class Elevator {
    public:
        Elevator();
        ~Elevator();

        std::vector<uint8_t> DecryptKey(const std::vector<uint8_t>& encryptedKey, const CLSID& clsid, const IID& iid, bool isEdge);

    private:
        bool m_initialized;
    };

}
