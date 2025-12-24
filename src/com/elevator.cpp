// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "elevator.hpp"
#include <stdexcept>
#include <sstream>

namespace Com
{

    Elevator::Elevator()
    {
        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (FAILED(hr))
            throw std::runtime_error("CoInitializeEx failed");
        m_initialized = true;
    }

    Elevator::~Elevator()
    {
        if (m_initialized)
            CoUninitialize();
    }

    std::vector<uint8_t> Elevator::DecryptKey(const std::vector<uint8_t> &encryptedKey, const CLSID &clsid, const IID &iid, bool isEdge)
    {
        BSTR bstrEnc = SysAllocStringByteLen(reinterpret_cast<const char *>(encryptedKey.data()), (UINT)encryptedKey.size());
        if (!bstrEnc)
            throw std::runtime_error("SysAllocStringByteLen failed");

        // RAII for BSTR
        struct BstrDeleter
        {
            void operator()(BSTR b) { SysFreeString(b); }
        };
        std::unique_ptr<OLECHAR[], BstrDeleter> encGuard(bstrEnc);

        BSTR bstrPlain = nullptr;
        DWORD comErr = 0;
        HRESULT hr = E_FAIL;

        if (isEdge)
        {
            Microsoft::WRL::ComPtr<IEdgeElevatorFinal> elevator;
            hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, &elevator);
            if (SUCCEEDED(hr))
            {
                CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
                                  RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                hr = elevator->DecryptData(bstrEnc, &bstrPlain, &comErr);
            }
        }
        else
        {
            Microsoft::WRL::ComPtr<IOriginalBaseElevator> elevator;
            hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, &elevator);
            if (SUCCEEDED(hr))
            {
                CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
                                  RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                hr = elevator->DecryptData(bstrEnc, &bstrPlain, &comErr);
            }
        }

        if (FAILED(hr))
        {
            std::ostringstream oss;
            oss << "DecryptData failed: 0x" << std::hex << hr;
            throw std::runtime_error(oss.str());
        }

        if (!bstrPlain)
            throw std::runtime_error("Decrypted key is null");

        std::unique_ptr<OLECHAR[], BstrDeleter> plainGuard(bstrPlain);
        UINT len = SysStringByteLen(bstrPlain);

        std::vector<uint8_t> result(len);
        memcpy(result.data(), bstrPlain, len);
        return result;
    }

}
