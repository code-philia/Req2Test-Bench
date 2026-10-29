"""The approved replacement selections, separate from Then policy.

Implements REFERENCE_CONTROL_TARGET_DISPOSITION_SPEC.md at 9c9d and the
Coddy full-282 specification section 3 (preparation PR #742). The
operator chooses one reviewed policy, never an arbitrary list of methods.
"""
from __future__ import annotations

POLICY = "r2t.reviewed-assertion-targets/1"


def _php(file, *methods):
    return tuple(("src/CoreShop/Behat/Context/" + file + ".php",
                  "CoreShop\\Behat\\Context\\" + file.replace("/", "\\"),
                  method) for method in methods)


_CORE = {
    "cart/rules/category_condition.feature:31": _php(
        "Domain/CartPriceRuleContext", "theSpecificPriceRuleForProductShouldBeInvalid"),
    "product/price_rules/category_condition.feature:29": _php(
        "Domain/ProductPriceRuleContext", "theSpecificPriceRuleForProductShouldBeInvalid"),
    "product/price_rules/category_condition.feature:35": _php(
        "Domain/ProductPriceRuleContext", "theSpecificPriceRuleForProductShouldBeInvalid"),
    "product/price_rules/category_condition.feature:41": _php(
        "Domain/ProductPriceRuleContext", "theSpecificPriceRuleForProductShouldBeValid"),
    "product/price_rules/stop_propagation.feature:30": _php(
        "Domain/ProductContext", "productPricesShouldBeExceptDiscountPrice"),
    "product/price_rules/stop_propagation.feature:36": _php(
        "Domain/ProductContext", "productPricesShouldBeExceptDiscountPrice"),
    "shipping/carrier_with_no_shipping_rules_valid.feature:20": _php(
        "Domain/ShippingContext", "carrierShouldBeValidForMyCart"),
    "cart/rules/free_shipping_action.feature:23": _php(
        "Domain/CartContext", "cartShippingCostShouldBeExcludingTax",
        "cartShippingCostShouldBeIncludingTax", "cartDiscountShouldBeIncludingTax",
        "cartTotalShouldBeIncludingTax"),
    "order/order_workflow_when_invoice_cancelled.feature:23": _php(
        "Domain/OrderContext", "orderInvoiceStateShouldBeState",
        "orderPaymentStateShouldBeState", "orderStateShouldBeState"),
    "order/order_workflow_when_shipment_cancelled.feature:23": _php(
        "Domain/OrderContext", "orderShippingStateShouldBeState",
        "orderPaymentStateShouldBeState", "orderStateShouldBeState"),
    "product/product_store_values_inheritance.feature:17": _php(
        "Domain/ProductContext", "productShouldBePriced"),
    "product/product_store_values_inheritance.feature:27": _php(
        "Domain/ProductContext", "productShouldBePriced"),
}
_JAVA_FILE = "src/test/java/com/algorand/algosdk/unit/IndexerResponses.java"
_JAVA_CLASS = "com.algorand.algosdk.unit.IndexerResponses"
TARGETS = {"coreshop/features/domain/" + item: definitions
           for item, definitions in _CORE.items()}
for _line, _method in (
    (106, "the_parsed_SearchAccounts_response_should_be_valid_on_round_and_the_array_should_be_of_len_and_the_element_at_index_should_have_authorizing_address"),
    (115, "the_parsed_SearchForTransactions_response_should_be_valid_on_round_and_the_array_should_be_of_len_and_the_element_at_index_should_have_rekey_to"),
):
    TARGETS[f"algorand-sdk/features/unit/v2indexerclient_responses.feature:{_line}"] = (
        (_JAVA_FILE, _JAVA_CLASS, _method),)


_SYLIUS = {
    "admin/product/managing_products/adding_associations_to_existing_product.feature:21": (
        "Admin/ManagingProductAssociationsContext", ("thisProductShouldHaveAnAssociation", "thisAssociationShouldHaveProducts")),
    "shop/cart/shopping_cart/adding_product_with_discounted_catalog_price_to_cart.feature:14": (
        "Shop/CartContext", ("iShouldSeeProductWithUnitPriceInMyCart", "iShouldSeeWithOriginalPriceInMyCart", "iShouldSeeOnlyWithUnitPriceInMyCart")),
    "shop/cart/shopping_cart/adding_product_with_discounted_catalog_price_to_cart.feature:23": (
        "Shop/CartContext", ("iShouldSeeProductWithDiscountedUnitPriceInMyCart", "iShouldSeeWithOriginalPriceInMyCart")),
    "shop/cart/shopping_cart/adding_products_with_quantity_to_cart.feature:12": (
        "Shop/CartContext", ("iShouldSeeWithQuantityInMyCart",)),
    "shop/promotion/receiving_discount/receiving_discounts_with_product_minimum_price_specified.feature:209": (
        "Shop/OrderContext", ("theShouldHaveUnitPricesDiscountedForAnd", "theShouldHaveUnitPriceDiscountedFor")),
    "shop/shipping/applying_shipping_method_rules/viewing_available_shipping_methods_based_on_items_total.feature:18": (
        "Shop/CheckoutContext", ("iShouldSeeShippingMethod", "iShouldNotSeeShippingMethod")),
}
for _item, (_file, _methods) in _SYLIUS.items():
    TARGETS["sylius/features/" + _item] = tuple(
        ("src/Sylius/Behat/Context/Api/" + _file + ".php",
         "Sylius\\Behat\\Context\\Api\\" + _file.replace("/", "\\"), method)
        for method in _methods)


GO_ITEM = "coddy-agent/features/cli_tui.feature:165"
GO_HANDLER = {"file": "external/cli/bdd_cli_tui_test.go", "line": 451,
    "start_byte": 14003, "end_byte": 14106, "name": "footerShowsUsage",
    "kind": "function_or_method", "signature": "func(text string) error"}
# Exact reviewed source also binds the receiver, absent from native signatures.
GO_SOURCE = ('func (s *cliTUIState) footerShowsUsage(text string) error {\n'
             '\treturn s.waitScreen(text, 3*time.Second)\n}')

GO_THUMBNAIL_ITEM = "coddy-agent/features/remote_api.feature:51"
GO_THUMBNAIL_HANDLERS = (
    {"file": "external/httpserver/bdd_remote_test.go", "line": 312,
     "start_byte": 9456, "end_byte": 9689, "name": "responseIsPNG",
     "kind": "function_or_method", "signature": "func() error"},
    {"file": "external/httpserver/bdd_remote_test.go", "line": 328,
     "start_byte": 9880, "end_byte": 10036, "name": "succeeds",
     "kind": "function_or_method", "signature": "func() error"},
)
GO_REVIEWED_HANDLERS = {GO_ITEM: (GO_HANDLER,), GO_THUMBNAIL_ITEM: GO_THUMBNAIL_HANDLERS}
GO_REVIEWED_SOURCES = {GO_ITEM: (GO_SOURCE,), GO_THUMBNAIL_ITEM: (
    (
        'func (s *remoteFeatureState) responseIsPNG() error {\n'
        '\tif s.contentType != "image/png" || !strings.HasPrefix(s.rawBody, "\\x89PNG\\r\\n\\x1a\\n") {\n'
        '\t\treturn errStatus("response is not a PNG thumbnail", s.status, s.rawBody)\n'
        '\t}\n'
        '\treturn nil\n'
        '}'
    ),
    (
        'func (s *remoteFeatureState) succeeds() error {\n'
        '\tif s.status < 200 || s.status >= 300 {\n'
        '\t\treturn errStatus("want 2xx", s.status, s.rawBody)\n'
        '\t}\n'
        '\treturn nil\n'
        '}'
    ),
)}


def reviewed_assertion_selection(closure: dict, *, policy: str | None = None) \
        -> dict | None:
    """Return the exact replacement, or None for unchanged default selection.

    Repeated invocations of one definition are normal. Each selected key must
    be bound in this item's closure, always removable and in its file set;
    the language transformer still proves unique source-method resolution.
    """
    from .strip import StripRefused, _definition_key

    if policy is None:
        return None
    if policy != POLICY:
        raise StripRefused(f"REFUSED: unknown assertion selection policy {policy!r}.")
    handlers = GO_REVIEWED_HANDLERS.get(closure.get("item_id"))
    if handlers is not None:
        for expected in handlers:
            matches = [step for step in closure.get("steps", [])
                if all(((step.get("definition") or {}).get("go", {}).get("handler") or {}).get(k) == v
                       for k, v in expected.items())]
            if not matches or expected["file"] not in closure.get("files", []) or any(
                    step.get("side") != "removable" for step in matches):
                raise StripRefused("REFUSED: reviewed Go assertion target missing or nonremovable.")
            # A changed repeated invocation must not silently disappear from selection.
            for step in closure.get("steps", []):
                handler = (step.get("definition") or {}).get("go", {}).get("handler") or {}
                if handler.get("file") == expected["file"] and handler.get("name") == expected["name"]:
                    if any(handler.get(k) != v for k, v in expected.items()):
                        raise StripRefused("REFUSED: reviewed Go assertion target changed.")
        return {"policy": POLICY, "handlers": [dict(h) for h in handlers]}
    targets = TARGETS.get(closure.get("item_id"))
    if targets is None:
        return None
    bound = {}
    for step in closure.get("steps") or []:
        bound.setdefault(_definition_key(step), []).append(step)
    for key in targets:
        if key not in bound or key[0] not in (closure.get("files") or []):
            raise StripRefused(
                f"REFUSED: reviewed assertion target {key!r} is not bound "
                f"in {closure.get('item_id')!r}'s gold closure.")
        if any(step.get("side") != "removable" for step in bound[key]):
            raise StripRefused(
                f"REFUSED: reviewed assertion target {key!r} is not "
                "exclusively removable.")
    return {"policy": POLICY, "definitions": [
        {"file": file, "class": cls, "method": method}
        for file, cls, method in sorted(targets)]}


def validate_assertion_selection(closure: dict, selection: dict) -> list[tuple]:
    """Language producers accept only the exact approved item selection."""
    from .strip import StripRefused

    expected = reviewed_assertion_selection(closure, policy=POLICY)
    if expected is None or selection != expected:
        raise StripRefused(
            "REFUSED: assertion selection differs from the reviewed item's "
            "complete replacement targets.")
    if "handlers" in expected:
        return [(h["file"], "go-handler", f"{h['start_byte']}:{h['end_byte']}")
                for h in expected["handlers"]]
    return [(entry["file"], entry["class"], entry["method"])
            for entry in expected["definitions"]]


def selftest() -> int:
    import copy
    import json
    from pathlib import Path
    from .strip import StripRefused

    assert len(TARGETS) == 20 and len(_CORE) == 12 and len(_SYLIUS) == 6
    declaration = json.loads((Path(__file__).resolve().parents[2] / "config"
        / "reference_control_dispositions.json").read_text(encoding="utf-8"))
    implemented = {item: {"policy": POLICY, "definitions": [
        {"file": file, "class": cls, "method": method}
        for file, cls, method in sorted(targets)]}
        for item, targets in TARGETS.items()}
    for item, handlers in GO_REVIEWED_HANDLERS.items():
        implemented[item] = {"policy": POLICY, "handlers": list(handlers)}
    assert declaration == implemented, "implemented targets differ from the approved declaration"
    for item, targets in TARGETS.items():
        closure = {"item_id": item, "files": sorted({t[0] for t in targets}),
                   "steps": [{"keyword": "When", "side": "removable",
                              "definition": dict(zip(("file", "class", "method"), key))}
                             for key in targets]}
        selection = reviewed_assertion_selection(closure, policy=POLICY)
        assert validate_assertion_selection(closure, selection) == sorted(targets)
        assert reviewed_assertion_selection(closure) is None
        for bad in (dict(closure, steps=[]), dict(closure, files=[])):
            try:
                reviewed_assertion_selection(bad, policy=POLICY)
            except StripRefused:
                pass
            else:
                raise AssertionError("missing target accepted")
        bad = copy.deepcopy(closure)
        bad["steps"][0]["side"] = "retained"
        try:
            reviewed_assertion_selection(bad, policy=POLICY)
        except StripRefused:
            pass
        else:
            raise AssertionError("retained target accepted")
        altered = copy.deepcopy(selection)
        altered["definitions"][0]["method"] += "Changed"
        try:
            validate_assertion_selection(closure, altered)
        except StripRefused:
            pass
        else:
            raise AssertionError("arbitrary replacement accepted")
    assert reviewed_assertion_selection({"item_id": "unlisted"}, policy=POLICY) is None
    # Both store-inheritance scenarios must retain the effective-Then action.
    # :17 used to derive successfully while stripping that action; :27 refused.
    from .strip import stripped_solution
    product = "src/CoreShop/Behat/Context/Domain/ProductContext.php"
    store = "src/CoreShop/Behat/Context/Setup/StoreContext.php"
    product_code = (
        "<?php\nclass ProductContext {\n"
        " public function productShouldBePriced() {\n  assert(true);\n }\n}\n")
    store_code = (
        "<?php\nclass StoreContext {\n"
        " public function iAmInStore($store) {\n"
        "  $this->fixedStoreContext->setStore($store);\n }\n}\n")
    for line in (17, 27):
        item = f"coreshop/features/domain/product/product_store_values_inheritance.feature:{line}"
        target = TARGETS[item][0]
        closure = {"item_id": item, "files": [product, store], "steps": [
            {"keyword": "When", "side": "removable", "definition":
             dict(zip(("file", "class", "method"), target))},
            {"keyword": "Then", "side": "removable", "definition": {
                "file": store, "class": "CoreShop\\Behat\\Context\\Setup\\StoreContext",
                "method": "iAmInStore"}}]}
        if line == 27:
            closure["steps"].append({**closure["steps"][1], "keyword": "Given"})
        selection = reviewed_assertion_selection(closure, policy=POLICY)
        derived = stripped_solution("unused", closure,
            source_texts={product: product_code, store: store_code},
            assertion_selection=selection)
        assert derived["files"] == [
            {"file_path": product, "code": product_code.replace("\n  assert(true);\n ", "\n ")},
            {"file_path": store, "code": store_code}]
        assert derived["metadata"] == {
            "source": "stripped_gold", "stripped_gold": True, "item_id": item,
            "assertion_selection": selection}
        if line == 17:
            old = stripped_solution("unused", closure,
                source_texts={product: product_code, store: store_code})
            assert "setStore" not in old["files"][1]["code"]
        else:
            try:
                stripped_solution("unused", closure,
                    source_texts={product: product_code, store: store_code})
            except StripRefused:
                pass
            else:
                raise AssertionError("historical shared-definition refusal changed")
    # Real Sylius disposition names with an effective-When assertion and an
    # action in the same PHP source: whole-body replacement preserves actions.
    for item, targets in TARGETS.items():
        if not item.startswith("sylius/"):
            continue
        file, cls, _ = targets[0]
        code = "<?php\nclass Context {\n public function action() { $this->cart->add(); }\n"
        for _, _, method in targets:
            code += f" public function {method}() {{ assert(true); }}\n"
        code += "}\n"
        closure = {"item_id": item, "files": [file], "steps": [
            {"keyword": "When", "side": "removable", "definition":
             {"file": file, "class": cls, "method": method}}
            for _, _, method in targets] + [{"keyword": "When", "side": "removable",
                "definition": {"file": file, "class": cls, "method": "action"}}]}
        derived = stripped_solution("unused", closure, source_texts={file: code},
            assertion_selection=reviewed_assertion_selection(closure, policy=POLICY))
        transformed = derived["files"][0]["code"]
        assert "assert(true)" not in transformed and "$this->cart->add();" in transformed
        assert all(method in transformed for _, _, method in targets)
    print("ALL PASS (assertion_selection)")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
