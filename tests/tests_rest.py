#  IRIS Source Code
#  Copyright (C) 2023 - DFIR-IRIS
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from unittest import TestCase
from iris import Iris


class TestsRest(TestCase):
    _subject = None

    @classmethod
    def setUpClass(cls) -> None:
        cls._subject = Iris()
        cls._subject.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._subject.stop()

    def test_create_asset_should_not_fail(self):
        response = self._subject.create_asset()
        self.assertEqual('success', response['status'])

    def test_get_api_version_should_not_fail(self):
        response = self._subject.get_api_version()
        self.assertEqual('success', response['status'])

    def test_create_case_should_return_201(self):
        response = self._subject.create_case({
            'case_name': 'name',
            'case_description': 'description',
            'case_customer': 1,
            'case_soc_id': ''
        })
        self.assertEqual(201, response.status_code)

    def test_create_case_with_missing_name_should_return_400(self):
        response = self._subject.create_case({
            'case_description': 'description',
            'case_customer': 1,
            'case_soc_id': ''
        })
        self.assertEqual(400, response.status_code)

    def test_create_case_with_classification_id_should_set_classification_id(self):
        response = self._subject.create_case({
            'case_name': 'name',
            'case_description': 'description',
            'case_customer': 1,
            'case_soc_id': '',
            'classification_id': 2
        }).json()
        self.assertEqual(2, response['classification_id'])

    def test_create_case_should_add_a_new_case(self):
        response = self._subject.get_cases()
        initial_case_count = len(response['data'])
        self._subject.create_case_deprecated()
        response = self._subject.get_cases()
        case_count = len(response['data'])
        self.assertEqual(initial_case_count + 1, case_count)

    def test_update_case_should_not_require_case_name_issue_358(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        response = self._subject.update_case(case_identifier, {'case_tags': 'test,example'})
        self.assertEqual('success', response['status'])

    def test_manage_case_filter_api_rest_should_fail(self):
        self._subject.create_case_deprecated()
        response = self._subject.get_cases_filter()
        self.assertEqual('success', response['status'])

    def test_get_case_graph_should_not_fail(self):
        response = self._subject.get('/case/graph/getdata')
        self.assertEqual('success', response['status'])

    def test_get_iocs_should_not_fail(self):
        response = self._subject.get('/case/ioc/list')
        self.assertEqual('success', response['status'])

    def test_create_case_template_should_not_be_forbidden_to_administrator(self):
        query_parameters = {
            'cid': 1
        }
        body = {
            'case_template_json': '{"name": "Template name"}',
        }
        response = self._subject.post('/manage/case-templates/add', body, query_parameters=query_parameters)
        # TODO should really be 201 here
        self.assertEqual(200, response.status_code)

    def test_update_settings_should_not_fail(self):
        body = {}
        response = self._subject.post('/manage/settings/update', body)
        print(response)

    def test_create_ioc_should_return_201(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        response = self._subject.create_ioc(case_identifier, {"ioc_type_id": 1, "ioc_tlp_id": 2, "ioc_value": "8.8.8.8", "ioc_description": "rewrw",
                                                              "ioc_tags": ""})
        self.assertEqual(201, response.status_code)

    def test_create_ioc_with_missing_ioc_value_should_return_400(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        response = self._subject.create_ioc(case_identifier, {"ioc_type_id": 1, "ioc_tlp_id": 2, "ioc_description": "rewrw", "ioc_tags": ""})
        self.assertEqual(400, response.status_code)

    def test_get_ioc_should_return_201(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        response = self._subject.create_ioc_deprecated()
        current_identifier = response['ioc_id']
        test = self._subject.get_iocs(current_identifier, case_identifier)
        self.assertEqual(current_identifier, test['ioc_id'])

    def test_get_ioc_with_missing_ioc_identifier_should_return_400(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        self._subject.create_ioc_deprecated()
        test = self._subject.get_iocs(None, case_identifier)
        self.assertEqual('error', test['status'])

    def test_delete_ioc_should_return_201(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        response = self._subject.create_ioc_deprecated()
        current_identifier = response['ioc_id']
        self._subject.delete_iocs(current_identifier, case_identifier)
        test = self._subject.get_iocs(current_identifier, case_identifier)
        self.assertEqual('Invalid IOC ID for this case', test)

    def test_delete_ioc_with_missing_ioc_identifier_should_return_400(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        response = self._subject.create_ioc_deprecated()
        current_identifier = response['ioc_id']
        self._subject.delete_iocs(None, case_identifier)
        test = self._subject.get_iocs(current_identifier, case_identifier)
        self.assertEqual(current_identifier, test['ioc_id'])

    def test_add_task_should_return_201(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        response = self._subject.add_tasks(case_identifier, {"task_assignees_id": [1], "task_description": "", "task_status_id": 1, "task_tags": "",
                                                         "task_title": "dummy title", "custom_attributes": {}})
        self.assertEqual(201, response.status_code)

    def test_add_task_with_missing_task_title_identifier_should_return_400(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        response = self._subject.add_tasks(case_identifier, {"task_assignees_id": [1], "task_description": "", "task_status_id": 1, "task_tags": "",
                                                        "custom_attributes": {}})
        self.assertEqual(400, response.status_code)

    def test_get_tasks_should_return_201(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        number = 1
        self._subject.add_tasks(case_identifier, {"task_assignees_id": [number], "task_description": "", "task_status_id": number, "task_tags": "",
                                                             "task_title": "dummy title", "custom_attributes": {}})
        test = self._subject.get_tasks(number)
        self.assertEqual(number, test['task_status_id'])

    def test_get_tasks_with_missing_ioc_identifier_should_return_400(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        number = 1
        self._subject.add_tasks(case_identifier, {"task_assignees_id": [number], "task_description": "", "task_status_id": 1, "task_tags": "",
                                                  "task_title": "dummy title", "custom_attributes": {}})
        test = self._subject.get_tasks(None)
        self.assertEqual('error', test['status'])

    def test_delete_task_should_return_201(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        number = 1
        self._subject.add_tasks(case_identifier, {"task_assignees_id": [number], "task_description": "", "task_status_id": 1, "task_tags": "",
                                                  "task_title": "dummy title", "custom_attributes": {}})
        test = self._subject.delete_tasks(number)
        self.assertEqual(201, test.status_code)

    def test_delete_task_with_missing_task_identifier_should_return_400(self):
        case = self._subject.create_case_deprecated()
        case_identifier = case['case_id']
        number = 1
        self._subject.add_tasks(case_identifier, {"task_assignees_id": [number], "task_description": "", "task_status_id": 1, "task_tags": "",
                                                  "task_title": "dummy title", "custom_attributes": {}})
        test = self._subject.delete_tasks(None)
        self.assertEqual(404, test.status_code)

