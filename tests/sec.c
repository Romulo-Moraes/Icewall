#include <stdio.h>
#include <check.h>
#define static
#include "../src/sec.c"
START_TEST(policy_rule) {
    bool eval = true;

    check_policy(&(struct rule_description) {.act = POLICY_ACCEPT}, &eval);
    ck_assert_int_eq(eval, true);

    check_policy(&(struct rule_description) {.act = POLICY_DROP}, &eval);
    ck_assert_int_eq(eval, true);

    check_policy(&(struct rule_description) {.act = 12}, &eval);
    ck_assert_int_eq(eval, false);
} END_TEST

START_TEST(port) {
    bool eval = true;

    check_p_rule(&(struct rule_description) {.p_rule = NO_P_RULE}, &eval);
    ck_assert_int_eq(eval, true); 

    eval = true;
    check_p_rule(&(struct rule_description) {.p_rule = SINGLE_P_RULE, .p_begin = 0}, &eval);
    ck_assert_int_eq(eval, true); 

    eval = true;
    check_p_rule(&(struct rule_description) {.p_rule = SINGLE_P_RULE, .p_begin = 30000}, &eval);
    ck_assert_int_eq(eval, true); 

    eval = true;
    check_p_rule(&(struct rule_description) {.p_rule = SINGLE_P_RULE, .p_begin = UINT16_MAX}, &eval);
    ck_assert_int_eq(eval, true); 

    eval = true;
    check_p_rule(&(struct rule_description) {.p_rule = P_RANGE_RULE, .p_begin = 30, .p_end = 20}, &eval);
    ck_assert_int_eq(eval, false); 

    eval = true;
    check_p_rule(&(struct rule_description) {.p_rule = P_RANGE_RULE, .p_begin = 0, .p_end = UINT16_MAX}, &eval);
    ck_assert_int_eq(eval, true); 

    eval = true;
    check_p_rule(&(struct rule_description) {.p_rule = P_RANGE_RULE, .p_begin = 90, .p_end = 90}, &eval);
    ck_assert_int_eq(eval, false); 

    eval = true;
    check_p_rule(&(struct rule_description) {.p_rule = P_RANGE_RULE, .p_begin = 90, .p_end = UINT16_MAX + 1}, &eval);
    ck_assert_int_eq(eval, false); 
} END_TEST

START_TEST(protocol) {
    bool eval = true;


    check_proto_rule(&(struct rule_description) {.proto_rule = NO_PROTO_RULE}, &eval);
    ck_assert_int_eq(eval, true);

    eval = true;
    check_proto_rule(&(struct rule_description) {.proto_rule = NO_PROTO_RULE}, &eval);
    ck_assert_int_eq(eval, true);

    eval = true;
    check_proto_rule(&(struct rule_description) {.proto_rule = TCP_PROTO_RULE}, &eval);
    ck_assert_int_eq(eval, true);

    eval = true;
    check_proto_rule(&(struct rule_description) {.proto_rule = UDP_PROTO_RULE}, &eval);
    ck_assert_int_eq(eval, true);

    eval = true;
    check_proto_rule(&(struct rule_description) {.proto_rule = 50}, &eval);
    ck_assert_int_eq(eval, false);

    eval = true;
    check_proto_rule(&(struct rule_description) {.proto_rule = 90}, &eval);
    ck_assert_int_eq(eval, false);
} END_TEST

START_TEST(addr) {
    bool eval = true;

    check_addr_rule(&(struct rule_description) {.ip_rule = NO_ADDR_RULE}, &eval);
    ck_assert_int_eq(eval, true);

    eval = true;
    check_addr_rule(&(struct rule_description) {.ip_rule = SINGLE_ADDR_RULE}, &eval);
    ck_assert_int_eq(eval, true);

    eval = true;
    check_addr_rule(&(struct rule_description) {.ip_rule = ADDR_SET_RULE, .pre_len = 0}, &eval);
    ck_assert_int_eq(eval, true);

    eval = true;
    check_addr_rule(&(struct rule_description) {.ip_rule = ADDR_SET_RULE, .pre_len = 32}, &eval);
    ck_assert_int_eq(eval, true);

    eval = true;
    check_addr_rule(&(struct rule_description) {.ip_rule = ADDR_SET_RULE, .pre_len = 33}, &eval);
    ck_assert_int_eq(eval, false);

    eval = true;
    check_addr_rule(&(struct rule_description) {.ip_rule = ADDR_SET_RULE, .pre_len = -1}, &eval);
    ck_assert_int_eq(eval, false);

    eval = true;
    check_addr_rule(&(struct rule_description) {.ip_rule = ADDR_SET_RULE, .pre_len = 16}, &eval);
    ck_assert_int_eq(eval, true);
} END_TEST

Suite* sec_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, policy_rule);
    tcase_add_test(tc_core, port);
    tcase_add_test(tc_core, protocol);
    tcase_add_test(tc_core, addr);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = sec_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? 0 : 1;
}