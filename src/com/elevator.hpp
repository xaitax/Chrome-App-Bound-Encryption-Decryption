// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include <wrl/client.h>
#include <string>
#include <vector>
#include <optional>

namespace Com {

    enum class ProtectionLevel {
        None = 0,
        PathValidationOld = 1,
        PathValidation = 2,
        Max = 3
    };

    // Interface definitions
    // Chrome/Brave IElevator interface (3 methods)
    MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
    IOriginalBaseElevator : public IUnknown {
    public:
        virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
        virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
        virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
    };

    // Avast's IElevatorChrome interface (12 methods - same vtable as base IElevator but properly registered)
    // Avast added 9 methods between RunRecoveryCRXElevated and EncryptData
    MIDL_INTERFACE("7737BB9F-BAC1-4C71-A696-7C82D7994B6F")
    IAvastElevator : public IUnknown {
    public:
        virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
        virtual HRESULT STDMETHODCALLTYPE UpdateSearchProviderElevated(const WCHAR*) = 0;
        virtual HRESULT STDMETHODCALLTYPE CleanupMigrateStateElevated(void) = 0;
        virtual HRESULT STDMETHODCALLTYPE UpdateInstallerLangElevated(const WCHAR*) = 0;
        virtual HRESULT STDMETHODCALLTYPE UpdateBrandValueElevated(const WCHAR*) = 0;
        virtual HRESULT STDMETHODCALLTYPE MigrateUninstallKeyElevated(const WCHAR*) = 0;
        virtual HRESULT STDMETHODCALLTYPE UpdateEndpointIdElevated(const char*) = 0;
        virtual HRESULT STDMETHODCALLTYPE UpdateFingerprintIdElevated(const char*) = 0;
        virtual HRESULT STDMETHODCALLTYPE RunMicroMVDifferentialUpdate(void) = 0;
        virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
        virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
        virtual HRESULT STDMETHODCALLTYPE DecryptData2(const BSTR, BSTR*, DWORD*) = 0;
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

    MIDL_INTERFACE("05EB264E-4D60-4F34-ADB7-1F983E930A79")
    IEdgeElevator3EdgeFinal : public IEdgeIntermediateElevator {
    public:
        virtual HRESULT STDMETHODCALLTYPE StoreDMToken(void) = 0;
        virtual HRESULT STDMETHODCALLTYPE DeleteDMToken(void) = 0;
    };

    MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
    IEdgeElevatorFinal : public IEdgeIntermediateElevator{};

    MIDL_INTERFACE("8F7B6792-784D-4047-845D-1782EFBEF205")
    IEdgeElevator2Final : public IEdgeIntermediateElevator {
    public:
        virtual HRESULT STDMETHODCALLTYPE RunIsolatedChrome(const WCHAR*, const WCHAR*, DWORD*, ULONG_PTR*) = 0;
        virtual HRESULT STDMETHODCALLTYPE AcceptInvitation(const WCHAR*) = 0;
    };

    // Copilot-specific interface (same methods, different IID for path validation)
    MIDL_INTERFACE("17DF149F-BE61-447E-A305-522F55021B36")
    IEdgeCopilotElevator : public IEdgeIntermediateElevator{};

    class Elevator {
    public:
        Elevator();
        ~Elevator();

        std::vector<uint8_t> DecryptKey(
            const std::vector<uint8_t>& encryptedKey,
            const CLSID& clsid,
            const IID& iid,
            const std::optional<IID>& iid_v2,
            bool isEdge,
            bool isAvast = false);

        // Decrypt using specific Edge IID (for testing Copilot vs Edge)
        std::vector<uint8_t> DecryptKeyEdgeIID(
            const std::vector<uint8_t>& encryptedKey,
            const CLSID& clsid,
            const IID& iid);

    private:
        bool m_initialized;
    };

}
